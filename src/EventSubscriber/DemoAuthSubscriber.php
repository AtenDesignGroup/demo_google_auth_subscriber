<?php

namespace Drupal\demo_google_auth_subscriber\EventSubscriber;

use Drupal\Core\Messenger\MessengerInterface;
use Drupal\social_api\Plugin\NetworkManager;
use Drupal\social_auth\AuthManager\OAuth2ManagerInterface;
use Drupal\social_auth\Event\SocialAuthEvents;
use Drupal\social_auth\Event\UserEvent;
use Drupal\social_auth\SocialAuthDataHandler;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Exception;
use Google_Client;
use Google_Service_Directory;


/**
 * Reacts on Social Auth events.
 * @package Drupal\demo_google_auth_subscriber\EventSubscriber
 */
class DemoAuthSubscriber implements EventSubscriberInterface
{
  /**
   * The messenger service.
   *
   * @var \Drupal\Core\Messenger\MessengerInterface
   */
  private $messenger;

  /**
   * The data handler.
   *
   * @var \Drupal\social_auth\SocialAuthDataHandler
   */
  private $dataHandler;

  /**
   * The network plugin manager.
   *
   * @var \Drupal\social_auth\SocialAuthDataHandler
   */
  private $networkManager;

  /**
   * The provider auth manager.
   *
   * @var \Drupal\social_auth\AuthManager\OAuth2ManagerInterface
   */
  private $providerAuth;

  /**
   * SocialAuthSubscriber constructor.
   *
   * @param \Drupal\Core\Messenger\MessengerInterface $messenger
   *   The messenger service.
   * @param \Drupal\social_auth\SocialAuthDataHandler $data_handler
   *   Used to manage session variables.
   * @param \Drupal\social_api\Plugin\NetworkManager $network_manager
   *   Used to get an instance of the social auth implementer network plugin.
   * @param \Drupal\social_auth\AuthManager\OAuth2ManagerInterface $providerAuth
   *   Used to get the provider auth manager.
   */
  public function __construct(
    MessengerInterface $messenger,
    SocialAuthDataHandler $data_handler,
    NetworkManager $network_manager,
    OAuth2ManagerInterface $providerAuth
  ) {

    $this->messenger = $messenger;
    $this->dataHandler = $data_handler;
    $this->networkManager = $network_manager;
    $this->providerAuth = $providerAuth;
  }


  /**
   * {@inheritdoc}
   *
   * Returns an array of event names this subscriber wants to listen to.
   * For this case, we are going to subscribe for user creation and login
   * events and call the methods to react on these events.
   */
  public static function getSubscribedEvents()
  {
    $events[SocialAuthEvents::USER_CREATED] = ['onUserCreated'];
    $events[SocialAuthEvents::USER_LOGIN] = ['onUserLogin'];

    return $events;
  }


  /**
   * When a user is created verify if they should be active right away
   *
   * @param \Drupal\social_auth\Event\UserEvent $event
   *   The Social Auth user event object.
   */
  public function onUserCreated(UserEvent $event)
  {
    //Get new user
    $user = $event->getUser();

    // Get user email to validate domain for setting active 
    $email = $user->getEmail();
    $parts = explode('@', $email);
    $domain = $parts[1];
    // Restict activating users to specific domain
    if ($domain === 'your_domain.com') {
      // Set domain user active
      $user->activate(true);
      $user->save();
      // Assign intial roles
      try {
        $this->determineRoles($user);
      } catch (Exception $e) {
        \Drupal::logger("demo_social_auth")->error("There was an issue assigning roles to user: " . $user->getEmail());
      }
    }
  }


  /**
   * When a user logs in verify their Google assigned group & set permissions
   *
   * @param \Drupal\social_auth\Event\UserEvent $event
   *   The Social Auth user event object.
   *
   */
  public function onUserLogin(UserEvent $event)
  {
    // Get the current user logging in
    $user = $event->getUser();

    //Get current roles and store incase of an error
    $currentRoles = $user->getRoles();

    try {
      // Remove all current roles
      foreach ($currentRoles as $role) {
        if ($role !== 0) {
          $user->removeRole($role);
          $user->save();
        }
      }
      // Get user roles from Google Group
      $this->determineRoles($user);
    } catch (Exception $e) {
      \Drupal::logger("demo_social_auth")->error("There was an issue assigning roles to user: " . $user->getDisplayName());
      // Reassigned saved roles on error
      foreach ($currentRoles as $role) {
        if ($role !== 0) {
          $user->addRole($role);
          $user->save();
        }
      }
    }
  }

  /**
   * Load in our JSON key file from a local location.
   */
  protected function getSecretsFile()
  {
    // You may need to setup your secret key for envinronment specific configurations
    // Otherwise you can just load the file from a safe location outside of the webroot
    if (file_exists(DRUPAL_ROOT . "/../files-private/googleAuth_key.json")) {
      return DRUPAL_ROOT . "/../files-private/googleAuth_key.json";
    }    
    // If no file exists
    return false;
  }

  /**
   * When a user logs in verify their Google assigned group & set permissions
   *
   * @param \Drupal\user\UserInterface $givenUser
   *   The passed in user object.
   *
   */
  protected function determineRoles($givenUser)
  {
    $KEY_FILE_LOCATION = $this->getSecretsFile();

    // Only run if we have the secrets file
    if ($KEY_FILE_LOCATION) {
      // 1. Admin SDK API must get enabled for relevant project in Dev Console.
      // 2. Service user must get created under relevant project and based on a user with
      // 3. User must have Groups Reader permission.
      // 4. Scope must get added to Sitewide Delegation.
      $user_to_impersonate = 'example_google_account@your_domain.com';
      $client = new Google_Client();
      $client->setAuthConfig($KEY_FILE_LOCATION);
      $client->setApplicationName('Get a Users Groups');
      $client->setSubject($user_to_impersonate);
      $client->setScopes([Google_Service_Directory::ADMIN_DIRECTORY_GROUP_READONLY]);
      $groups = new Google_Service_Directory($client);

      $params = [
        'userKey' => $givenUser->getEmail(),
      ];
      $results = $groups->groups->listGroups($params);

      // Hold Map for roles based on Google Groups
      $roleAssignment = [
        "Author Group Name" => "author",
        "Editor Group Name" => "editor",
        "Publisher Group Name" => "publisher",
      ];

      // Loop through the user's groups an add approved roles to array
      foreach ($results['groups'] as $result) {
        $name = $result['name'];

        //Assign roles based on what was determined
        if (array_key_exists($name, $roleAssignment)) {
          $givenUser->addRole($roleAssignment[$name]);
          $givenUser->save();
        }
      }
    }
  }
}
