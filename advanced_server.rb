require 'sinatra'
require 'octokit'
require 'json'
require 'openssl' # Used to verify the webhook signature
require 'jwt'     # Used to authenticate a GitHub App
require 'time'    # Used to get ISO 8601 representation of a Time object
require 'logger'

set :port, 3000


# This is template code to create a GitHub App server.
# You can read more about GitHub Apps here: # https://developer.github.com/apps/
#
# On its own, this app does absolutely nothing, except that it can be installed.
# It's up to you to add fun functionality!
# You can check out one example in advanced_server.rb.
#
# This code is a Sinatra app, for two reasons:
#   1. Because the app will require a landing page for installation.
#   2. To easily handle webhook events.
#
#
# Of course, not all apps need to receive and process events!
# Feel free to rip out the event handling code if you don't need it.
#
# Have fun!
#

class GHAapp < Sinatra::Application

  # !!! DO NOT EVER USE HARD-CODED VALUES IN A REAL APP !!!
  # Instead, set and read app tokens or other secrets in your code
  # in a runtime source, like an environment variable like below

  # Expects that the private key has been set as an environment variable in
  # PEM format using the following command to replace newlines with the
  # literal `\n`:
  #   export GITHUB_PRIVATE_KEY=`awk '{printf "%s\\n", $0}' private-key.pem`
  #
  # Converts the newlines
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

  # Your registered app must have a secret set. The secret is used to verify
  # that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end


  # Before each request to the `/event_handler` route
  before '/event_handler' do
    get_payload_request(request)
    verify_webhook_signature
    authenticate_app
    # Authenticate each installation of the app in order to run API operations
    authenticate_installation(@payload)
  end


  post '/event_handler' do
    # Get the event type from the HTTP_X_GITHUB_EVENT header
    case request.env['HTTP_X_GITHUB_EVENT']

    when 'check_suite'
      # A new check_suite has been created. Create a new check run with status queued
      if @payload['action'] === 'requested' || @payload['action'] === 'rerequested'
        create_check_run
      end

    when 'check_run'
      # GH confirms our new check_run has been created, or rerequested. Update it to "completed"
      # Notice that we get notifications of the check runs created by _other_ systems than ours!
      # We need to be selective, hence the conditional on the app id. We only want to process our _own_
      # check runs. That's why we check if the app id is == APP_IDENTIFIER
      if @payload['check_run']['app']['id'].to_s === APP_IDENTIFIER
        case @payload['action']
        when 'created'
          initiate_check_run
        when 'rerequested'
          create_check_run
        when 'requested_action'
          take_requested_action
        end
      end
    end
  end


  helpers do

    # Create a new check run
    def create_check_run
      # Octokit doesn't yet support the checks API, but it does provide generic HTTP methods we can use!
      # https://developer.github.com/v3/checks/runs/#create-a-check-run
      check_run = @installation_client.post("repos/#{@payload['repository']['full_name']}/check-runs", {
          accept: 'application/vnd.github.antiope-preview+json', # This header allows for beta access to Checks API
          name: 'Octo Rubocop',
          # The information we need should probably be pulled from persistent storage, but we can
          # use the event that triggered the run creation. However, the structure differs depending on whether
          # it was a check run or a check suite event that trigged this call.
          head_sha: @payload['check_run'].nil? ? @payload['check_suite']['head_sha'] : @payload['check_run']['head_sha']
      })

      # We've now requested the creation of a check run from GitHub. We will wait until we get a confirmation
      # from GitHub, and then kick off our CI process from there.
    end

    # Start the CI process
    def initiate_check_run
      # This method is called in response to GitHub acknowledging our request to create a check run.
      # We'll first update the check run to "in progress"
      # Then we'll run our CI process
      # Then we'll update the check run to "completed" with the CI results.

      # Octokit doesn't yet support the Checks API, but it does provide generic HTTP methods we can use!
      # https://developer.github.com/v3/checks/runs/#update-a-check-run
      # notice the verb! PATCH!
      updated_check_run = @installation_client.patch("repos/#{@payload['repository']['full_name']}/check-runs/#{@payload['check_run']['id']}", {
          accept: 'application/vnd.github.antiope-preview+json', # This header is necessary for beta access to Checks API
          name: 'Octo Rubocop',
          status: 'in_progress',
          started_at: Time.now.utc.iso8601
      })

      # ***** RUN A CI TEST *****
      # This is where we would kick off our CI process. Ideally this would be performed async, so we could
      # return immediately. But for now we'll do a simulated CI process syncronously, and update the check run right here..

      full_repo_name = @payload['repository']['full_name']
      repository     = @payload['repository']['name']
      head_sha       = @payload['check_run']['head_sha']
      repository_url = @payload['repository']['html_url']

      clone_repository(full_repo_name, repository, head_sha)

      @report = `rubocop '#{repository}/*' --format json` # --auto-correct`
      `rm -rf #{repository}`
      @output = JSON.parse @report
      annotations = []

      if @output["summary"]["offense_count"] == 0
        conclusion = 'success'
      else
        conclusion = 'neutral'
        @output["files"].each do |file|
          file_path = file["path"].gsub(/#{repository}\//,'')
          blob_href = "#{repository_url}/blob/#{head_sha}/#{file_path}"
          warning_level = 'notice'
          file["offenses"].each do |offense|
            start_line   = offense["location"]["start_line"]
            end_line     = offense["location"]["last_line"]
            start_column = offense["location"]["start_column"]
            end_column   = offense["location"]["last_column"]
            message      = offense["message"]
            annotation = {
              "filename" => file_path,
              "blob_href" => blob_href,
              "start_line" => start_line,
              "end_line" => end_line,
              "start_column" => start_column,
              "end_column" => end_column,
              "warning_level" => warning_level,
              "message" => message
            }
            annotations.push(annotation)
          end
        end
      end

      summary = "Octoc Rubocop summary\n-Offense count: #{@output["summary"]["offense_count"]}\n-File count: #{@output["summary"]["target_file_count"]}\n-Target file count: #{@output["summary"]["inspected_file_count"]}}"
      details = "Octoc Rubocop version: #{@output["metadata"]["rubocop_version"]}"

      # Now, mark the check run as complete! And if there are warnings, share them
      updated_check_run = @installation_client.patch("repos/#{@payload['repository']['full_name']}/check-runs/#{@payload['check_run']['id']}", {
          accept: 'application/vnd.github.antiope-preview+json', # This header is necessary for beta access to Checks API
          name: 'Octo Rubocop',
          status: 'completed',
          conclusion: conclusion,
          completed_at: Time.now.utc.iso8601,
          output: {
            title: "Octoc Rubocop",
            summary: summary,
            details: details,
            annotations: annotations
          },
          actions: [{
            label: "Fix this",
            description: "Automatically fix all linter notices.",
            identifier: "fix_rubocop_notices"
          }]
      })

    end

    def take_requested_action
      full_repo_name = @payload['repository']['full_name']
      repository     = @payload['repository']['name']
      head_sha       = @payload['check_run']['head_sha']
      head_branch    = @payload['check_run']['check_suite']['head_branch']
      repository_url = @payload['repository']['html_url']

      if(@payload['requested_action']['identifier'] == 'fix_rubocop_notices')
        clone_repository(full_repo_name, repository, head_sha, head_branch)

        @report = `rubocop '#{repository}/*' --format json --auto-correct`
        pwd = Dir.getwd()
        Dir.chdir(repository)
        `git add .`
        `git commit -am 'Automatically fix Octo Rubocop notices.'`
        `git push 'https://github.com/#{full_repo_name}.git' #{head_branch}`
        Dir.chdir(pwd)
        `rm -rf #{repository}`
      end
    end

    def clone_repository(full_repo_name, repository, head_sha, head_branch=nil)
      `git clone 'https://x-access-token:#{@installation_token.to_s}@github.com/#{full_repo_name}.git'`
      pwd = Dir.getwd()
      Dir.chdir(repository)
      `git pull`
      if(head_branch.nil?)
        `git checkout '#{head_sha}'`
      else
        `git checkout '#{head_branch}'`
      end
      Dir.chdir(pwd)
    end

    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      # request.body is an IO or StringIO object
      # Rewind in case someone already read it
      request.body.rewind
      # The raw text of the body is required for webhook signature verification
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue => e
        fail  "Invalid JSON (#{e}): #{@payload_raw}"
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    # GitHub App authentication equires that we construct a
    # JWT (https://jwt.io/introduction/) signed with the app's private key,
    # so GitHub can be sure that it came from the app an not altererd by
    # a malicious third party.
    def authenticate_app
      payload = {
          # The time that this JWT was issued, _i.e._ now.
          iat: Time.now.to_i,

          # JWT expiration time (10 minute maximum)
          exp: Time.now.to_i + (10 * 60),

          # Your GitHub App's identifier number
          iss: APP_IDENTIFIER
      }

      # Cryptographically sign the JWT
      jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

      # Create the Octokit client, using the JWT as the auth token.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)
    end

    # Instantiate an Octokit client authenticated as an installation of a
    # GitHub App to run API operations.
    def authenticate_installation(payload)
      installation_id = payload['installation']['id']
      installation_token = @app_client.create_app_installation_access_token(installation_id)[:token]
      @installation_client = Octokit::Client.new(bearer_token: installation_token)
    end

    # Check X-Hub-Signature to confirm that this webhook was generated by
    # GitHub, and not a malicious third party.
    #
    # GitHub will the WEBHOOK_SECRET, registered
    # to the GitHub App, to create a hash signature sent in each webhook payload
    # in the `X-HUB-Signature` header. This code computes the expected hash
    # signature and compares it to the signature sent in the `X-HUB-Signature`
    # header. If they don't match, this request is an attack, and we should
    # reject it. GitHub uses the HMAC hexdigest to compute the signature. The
    # `X-HUB-Signature` looks something like this: "sha1=123456"
    # See https://developer.github.com/webhooks/securing/ for details
    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
      halt 401 unless their_digest == our_digest

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- recevied event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end

  end


  # Finally some logic to let us run this server directly from the commandline, or with Rack
  # Don't worry too much about this code ;) But, for the curious:
  # $0 is the executed file
  # __FILE__ is the current file
  # If they are the same—that is, we are running this file directly, call the Sinatra run method
  run! if __FILE__ == $0
end
