<?php
namespace SimpleWebHook {

  /**
   * Simple Web Hook
   * Dan's Simple Git WebHook Receiver for PHP
   *
   * @version 0.0.1
   * @author Daniel Wilson <contact@danw.io>
   * @license GNU GPLv3
   *
   * https://danw.io/git-webhook-project/
   * https://github.com/Danw33/simple-web-hook
   *
   * Avialable under the GNU GPLv3 License
   * See the LICENSE and README.md for more information.
   */
  class SimpleWebHook {
    private $_eventType, $_eventGuid, $_signature, $_remoteUA = null;
    private $_eventRawPayload = null;
    private $_eventPayload, $_eventResponse, $_debugInfo, $_branches = array();
    private $_remoteUAVerified = false;

    /** Constructs a new instance of SimpleWebHook */
    public function __construct(){
      // Something may go here one day...
    }

    /**
     * Handle the hook delivery. This is considered the main method for the class.
     * @since 0.0.1
     */
    public function handleDelivery(){
      global $_SERVER, $_REQUEST, $_GET, $_POST;

      // Verify Request Method (Must be POST, 404 for anything else)
      if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] !== 'POST') {
        header('404 Not Found', 404, true);
        exit();
      };

      // Verify Connection Security (Encrypted Deliveries Only!)
      if ((isset($_SERVER['HTTPS'] && $_SERVER['HTTPS'] !== 'on') || !isset($_SERVER['HTTPS']) $this->dieWithStatus('Payloads should only be delivered over secure connections! (You <-/-> Me)', 400);
      if (isset($_SERVER['HTTP_CF_ORIGIN_HTTPS']) && $_SERVER['HTTP_CF_ORIGIN_HTTPS'] !== 'on') $this->dieWithStatus('Payloads should only be delivered over secure connections! (You <-/-> Edge <--> Me)', 400);

      // Get and Verify the remote User Agent
      isset($_SERVER['HTTP_USER_AGENT']) ? $this->_remoteUA = (string)$_SERVER['HTTP_USER_AGENT'] : $this->dieWithStatus('No User-Agent Detected!', 400);
      0 !== strpos($this->_remoteUA, 'GitHub-Hookshot/') ? $_remoteUAVerified = (bool)true : $this->dieWithStatus('User-Agent Verification Failed!', 400);

      // Check for and gather the request headers into variables
      isset($_REQUST['X-GitHub-Event']) ? $this->_eventType = (string)$_REQUST['X-GitHub-Event'] : $this->dieWithStatus('Missing X-GitHub-Event Header!', 400);
      isset($_REQUST['X-GitHub-Delivery']) ? $this->_eventGuid = (string)$_REQUST['X-GitHub-Delivery'] : $this->dieWithStatus('Missing X-GitHub-Delivery Header!', 400);
      isset($_REQUST['X-GitHub-Signature']) ? $this->_signature = (string)$_REQUST['X-GitHub-Signature'] : $this->dieWithStatus('Missing X-GitHub-Signature Header!', 400);

      // Gather the raw request payload
      isset($_POST['payload']) $this->_eventRawPayload = (string)$_POST['payload'] : $this->dieWithStatus('Missing Payload!', 400);

      // Gather some debug data for later
      $this->setRequestDebugInfo();

      // Get some info from the system
      $this->_sysUsr = $this->runSystemCmd(SimpleWebHook\Shell::WhoAmI);
      $this->_sysPwd = $this->runSystemCmd(SimpleWebHook\Shell::Pwd);
      $this->_sysGitPath = $this->runSystemCmd(SimpleWebHook\Shell::Which, SimpleWebHook\Shell::Git);



      // Decode and the payload array
      $this->setPayloadData($this->decodePayload());

      // Validate the payload and process it
      $this->validatePayload ? return $this->processPayload((array)$this->_eventPayload) : $this->dieWithStatus('Payload Verification Failed!', 400);
    }

    /**
     * Decodes and returns the JSON payload as an array
     *
     * @since 0.0.1
     * @param $rawData string The raw JSON Payload, as a string.
     * @return array The decoded JSON Payload, as an array.
     */
    protected function decodePayload($rawData){
      return json_decode(stripslashes($rawData));
    }

    /**
     * Sets the payload for this instance from the given array.
     *
     * @see SimpleWebHook::decodePaylod()
     *
     * @since 0.0.1
     * @param $decodedPayload array The decoded JSON Payload array
     */
    protected function setPayloadData($decodedPayload){
      $this->_eventPayload = $decodedPayload;
      return;
    }

    /**
     * Sets Debug Information for the HTTP Request
     */
    protected function setRequestDebugInfo(){
      if (isset($_SERVER['HTTP_CF_CONNECTING_IP'])) $this->_debugInfo['HTTP_CF_CONNECTING_IP'] = (string)$_SERVER['HTTP_CF_CONNECTING_IP'];
      if (isset($_SERVER['HTTP_CF_IPCOUNTRY'])) $this->_debugInfo['HTTP_CF_IPCOUNTRY'] = (string)$_SERVER['HTTP_CF_IPCOUNTRY'];
      if (isset($_SERVER['HTTP_CF_ORIGIN_HTTPS'])) $this->_debugInfo['HTTP_CF_ORIGIN_HTTPS'] = (string)$_SERVER['HTTP_CF_ORIGIN_HTTPS'];
      if (isset($_SERVER['HTTP_CF_RAY'])) $this->_debugInfo['HTTP_CF_RAY'] = (string)$_SERVER['HTTP_CF_RAY'];
      if (isset($_SERVER['HTTP_CF_VISITOR'])) $this->_debugInfo['HTTP_CF_VISITOR'] = (string)$_SERVER['HTTP_CF_VISITOR'];
      if (isset($_SERVER['HTTP_CF_RAILGUN'])) $this->_debugInfo['HTTP_CF_RAILGUN'] = (string)$_SERVER['HTTP_CF_RAILGUN'];
      if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) $this->_debugInfo['HTTP_X_FORWARDED_FOR'] = (string)$_SERVER['HTTP_X_FORWARDED_FOR'];
      if (isset($_SERVER['HTTP_X_FORWARDED_PROTO'])) $this->_debugInfo['HTTP_X_FORWARDED_PROTO'] = (string)$_SERVER['HTTP_X_FORWARDED_PROTO'];
      if (isset($_SERVER['REMOTE_ADDR'])) $this->_debugInfo['REMOTE_ADDR'] = (string)$_SERVER['REMOTE_ADDR'];
      if (isset($_SERVER['SERVER_ADDR'])) $this->_debugInfo['SERVER_ADDR'] = (string)$_SERVER['SERVER_ADDR'];
      if (isset($_SERVER['PHP_AUTH_USER'])) $this->_debugInfo['PHP_AUTH_USER'] = (string)$_SERVER['PHP_AUTH_USER'];
      if (isset($_SERVER['PHP_SELF'])) $this->_debugInfo['PHP_SELF'] = (string)$_SERVER['PHP_SELF'];
      if (isset($_SERVER['PHP_AUTH_USER'])) $this->_debugInfo['PHP_AUTH_USER'] = (string)$_SERVER['PHP_AUTH_USER'];
      if (isset($_SERVER['SERVER_PROTOCOL'])) $this->_debugInfo['SERVER_PROTOCOL'] = (string)$_SERVER['SERVER_PROTOCOL'];
      if (isset($_SERVER['REQUEST_TIME_FLOAT'])) $this->_debugInfo['REQUEST_TIME_FLOAT'] = (string)$_SERVER['REQUEST_TIME_FLOAT'];
      return;
    }

    /**
     * Process the payload
     * The payload should be an array, already decoded from the payload JSON
     *
     * @since 0.0.1
     * @param $payload array Payload Data
     */
    protected function processPayload($payload){
      // See what the event is
      isset($payload['event']) ? switch () {
        case 'push':
          // Any Git push to a Repository, including editing tags or branches. Commits via API actions that update references are also counted. This is the default event.
          $response = array();
          $response['status'] = addslashes($this->runSystemCmd(SimpleWebHook\Git::Status));
          $response['fetch_all'] = addslashes($this->runSystemCmd(SimpleWebHook\Git::FetchAll));
          $response['pull'] = addslashes($this->runSystemCmd(SimpleWebHook\Git::Pull));
          $this->sendSuccessResponse(array('success' => (bool)true, 'message' => 'Push event received successfully.', 'console' => $response));
          break;
        case '*':
          // Wildcard Event: Any Time any event is triggered.
        case 'commit_comment':
          // Any time a Commit is commented on.
        case 'create':
          // Any time a Branch or Tag is created.
          $response = array();
          $response['status'] = addslashes($this->runSystemCmd(SimpleWebHook\Git::Status));
          $response['fetch_all'] = addslashes($this->runSystemCmd(SimpleWebHook\Git::FetchAll));
          $this->sendSuccessResponse(array('success' => (bool)true, 'message' => 'Create event received successfully (Local status updated with fetch all).', 'console' => $response));
          break;
        case 'delete':
          // Any time a Branch or Tag is deleted.
          $response = array();
          $response['status'] = addslashes($this->runSystemCmd(SimpleWebHook\Git::Status));
          $response['fetch_all'] = addslashes($this->runSystemCmd(SimpleWebHook\Git::FetchAll));
          $this->sendSuccessResponse(array('success' => (bool)true, 'message' => 'Delete event received successfully (Local status updated with fetch all).', 'console' => $response));
          break;
        case 'deployment':
          // Any time a Repository has a new deployment created from the API.
        case 'deployment_status':
          // Any time a deployment for a Repository has a status update from the API.
        case 'fork':
          // Any time a Repository is forked.
        case 'gollum':
          // Any time a Wiki page is updated.
        case 'issue_comment':
          // Any time an Issue or Pull Request is commented on.
        case 'issues':
          // Any time an Issue is assigned, unassigned, labeled, unlabeled, opened, closed, or reopened.
        case 'member':
          // Any time a User is added as a collaborator to a non-Organization Repository.
        case 'membership':
          // Any time a User is added or removed from a team. Organization hooks only.
        case 'page_build':
          // Any time a Pages site is built or results in a failed build.
        case 'public':
          // Any time a Repository changes from private to public.
        case 'pull_request_review_comment':
          // Any time a comment is created on a portion of the unified diff of a pull request (the Files Changed tab).
        case 'pull_request':
          // Any time a Pull Request is assigned, unassigned, labeled, unlabeled, opened, closed, reopened, or synchronized (updated due to a new push in the branch that the pull request is tracking).
        case 'repository':
          // Any time a Repository is created. Organization hooks only.
        case 'release':
          // Any time a Release is published in a Repository.
        case 'status':
          // Any time a Repository has a status update from the API
        case 'team_add':
          // Any time a team is added or modified on a Repository.
        case 'watch':
          // Any time a User stars a Repository.
        default:
          // Not a configured event - GitHub may have added new ones?
          $response = 'Payload received but event ' . addslashes($payload['event']) . ' is not configured, No action was taken.'
          $this->sendSuccessResponse(array('success' => (bool)true, 'message' => $response));
      } : $this->dieWithStatus('Payload did not contain an event.', 400);

      // Normally, we won't end up here, A status and exit() or an error and die() should have been called
      return;
    }

    /**
     * Runs a command on the underlying OS. The given command must be one of the several
     * pre-determined commands, and cannot be passed directly.
     *
     * @since 0.0.1
     * @param $command const Command Constant from Shell or Git Classes
     * @param $options string (Optional) Extra options to pass on the command-line.
     *
     * @return Response
     */
    protected function runSystemCmd($command, $options = null){
      if(defined($command) && !empty($command)){
        // Command is a constant, and not empty. Should we do more checks here?
        // Add the options to it, if they are set
        $stdin = !empty($options) ? $command . ' ' . $options : $command;

        // Run the command
        $stdout = shell_exec($stdin);

        // Return the result
        return trim($stdout);
      }
    }

    /**
     * Fatal Error Method, Returns the given HTTP Response Code and calls die() with the error message.
     * Error messages will be JSON-encoded.
     *
     * @since 0.0.1
     * @param $message string The error message to return to the client
     * @param $response int The HTTP Response code (Default: 500)
     */
    protected function dieWithStatus($message, $response = 500){
      // Set Response headers
      header('Content-Type: application/json; charset=utf-8');
      header('X-Hook-Result: Error');

      // Set Response Code
      header((string)$response, (int)$response, (bool)true);

      // JSON-encode the error
      $jsonError = json_encode(array('error' => (bool)true, 'message' => addslashes((string)$message));

      // Die with the error message
      die($jsonError);
    }

    /**
     * Final Response Method, Responds to the request with a JSON status
     *
     * @since 0.0.1
     * @param $responseData array Response Data, to be JSON encoded.
     */
    protected function sendSuccessResponse($responseData){
      header('Content-Type: application/json; charset=utf-8');
      header('X-Hook-Result: Success');
      echo json_encode($responseData);
      exit();
    }

    /**
     * Adds a new repository path to the array, and ties it to a specific branch
     *
     * If the given $branch already has a path, it will be overwritten.
     *
     * @since 0.0.1
     * @param $branch string Git branch
     * @param $path string Local respository path
     */
    protected function setBranchPath($branch, $path){
      $this->_branches[$branch] = $path;
      return;
    }

    /**
     *
     */
    protected function nothing(){

    }
  }

  /**
   * Shell Subclass
   * Contains constants which represent actual shell commands.
   *
   * Cannot be instantised or extended for security reasons.
   *
   * @abstract
   * @author Daniel Wilson
   * @license GNU GPLv3
   * @since 0.0.1
   * @package SimpleWebHook
   */
  abstract class Shell
  {
      // Prevent easily extending this class
      private function __construct(){ return; }

      // Constants (Command Enumerations)

      /** whoami */
      const WhoAmI = 'whoami';
      /** pwd */
      const Pwd = 'pwd';
      /** git */
      const Git = 'git';
      /** which */
      const Which = 'which';
  }

  /**
   * Git Subclass
   * Contains constants which represent actual git commands.
   *
   * Cannot be instantised or extended for security reasons.
   *
   * @abstract
   * @author Daniel Wilson
   * @license GNU GPLv3
   * @since 0.0.1
   * @package SimpleWebHook
   */
  abstract class Git
  {
      // Prevent easily extending this class
      private function __construct(){ return; }

      // Constants (Command Enumerations)

      /** git status */
      const Status = 'git status';
      /** git fetch */
      const Fetch = 'git fetch';
      /** git fetch --all */
      const FetchAll = 'git fetch --all';
      /** git pull */
      const Pull = 'git pull';
      /** git submodule sync */
      const SubmoduleSync = 'git submodule sync';
      /** git submodue update --recursive */
      const SubmoduleUpdate = 'git submodule update --recursive';
      /** git submodule status */
      const SubmoduleStatus = 'git submodule status';
  }
}

// Fire it up
$swh = new SimpleWebHook\SimpleWebHook();
$swh->setBranchPath('master', '/srv/www/public_html');
$swh->setBranchPath('develop', '/srv/www/dev');
$swh->handleDelivery();
