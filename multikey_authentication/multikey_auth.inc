<?php


/**
 * @file
 *  The implementation of the key authentication scheme
 */

/**
 * Function to
 *
 * @param unknown_type $settings
 * @return unknown
 */
function _multikey_auth_security_settings($settings) {
  $form = array();

  $service_keys = multikey_auth_get_keys();

  $form['multikey_auth_use_key'] = array(
    '#type'           => 'checkbox',
    '#title'          => t('Use keys for this service'),
    '#default_value'  => isset($settings['multikey_auth_use_key']) ? $settings['multikey_auth_use_key'] : TRUE,
    '#description'    => t('When enabled all method calls from these should have an key authentication.'),
  );


  $header = array(
    'title'  => t('Title'),
    'service_key'    => t('Key'),
  );


  $form['multikey_auth'] = array(
    '#type'          => 'tableselect',
    '#title'         => t('Multiple API Keys'),
    '#header'        => $header,
    '#options'       => $service_keys,
    '#empty'         => t('No content available.'),
    '#default_value' => isset($settings['multikey_auth']) ? $settings['multikey_auth'] : TRUE,
    '#description'   => t('Check the keys with domain in which it can be used')
  );

  return $form;
}


/**
 * Authenticates a call using key  to verify the request.
 *
 * @param array $settings
 *  The settings for the authentication module.
 * @param array $method
 *  The method that's being called
 * @param array $args
 *  The arguments that are being used to call the method
 * @return void|string
 *  Returns nothing, or a error message if authentication fails
 */
function _multikey_auth_authenticate_call($settings, $method, $args) {

  /**
   * @todo
   * 1. Need to extend the security like services_key auth module
   * 2. Auto save of services keys when deleted from table
   */
  if ($settings['multikey_auth_use_key']) {

    // we direclty get the key the check for the selection in the service
    // deletion of the key will not remove the same from the service authentication
    $key = $_GET['key'];

    //check whether the key is available in database and the same
    if (!in_array($key, $settings['multikey_auth'], TRUE) ) {
      return services_error(t('Invalid API key.'), 401);
    }

    //Fetch all the request headers
    $headers = getallheaders();

    $url = array_key_exists('Referer', $headers) ? ($headers['Referer']) : '';
    if (empty($url)) {
      $url = $headers['Origin'];
      if (empty($url)) {
        $url = $_GET['referrer'];  // This is instructed by James and gokul fearing referrer is not sent by browser some times
      }
    }
    $url_components = parse_url($url);
    $domain         = $url_components['host'];
    $domain         = preg_replace('/^www./', '', $domain);

    //next need to check whether key matches with the domain
    if (!services_authenticate_domain($domain, $key)) {
      return services_error(t('Invalid API key and domain.'), 401);
    }

  }

}