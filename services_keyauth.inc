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
function _services_keyauth_security_settings($settings) {
  $form = array();

  $form['services_keyauth'] = array(
    '#type'          => 'textfield',
    '#default_value' => isset($settings['services_keyauth']) ? $settings['services_keyauth'] : '',
    '#title'         => t('Authentication Key'),
    '#required'      => TRUE,
    '#description'   => t('Paste the key created using the link <a target="_blank" href="/admin/structure/services/keys/add">here</a>.This key is need for authentication for this service.'),
  );

  $form['services_keyauth_use_key'] = array(
    '#type'           => 'checkbox',
    '#title'          => t('Use keys for this service'),
    '#default_value'  => isset($settings['services_keyauth_use_key']) ? $settings['services_keyauth_use_key'] : TRUE,
    '#description'    => t('When enabled all method calls from these should have an key authentication.'),
  );

  $form['services_key_expiry'] = array(
   '#type'           => 'textfield',
   '#prefix'         => "<div id='services-key-expiry'>",
   '#suffix'         => "</div>",
   '#title'          => t('Token expiry time'),
   '#default_value'  => isset($settings['services_key_expiry']) ? $settings['services_key_expiry'] : 30,
   '#description'    => t('The time frame for which the token will be valid. Default is 30 secs.'),
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
function _services_keyauth_authenticate_call($settings, $method, $args) {

  if ($settings['services_keyauth_use_key']) {
     
    $hash = $_GET['hash'];
    $domain = $_GET['domain_name'];
    $timestamp = $_GET['domain_time_stamp'];
    $nonce = $_GET['nonce'];
    $key = $_GET['key'];

    $expiry_time = $timestamp + $settings['services_key_expiry'];

    if ($expiry_time < REQUEST_TIME) {
      return services_error(t('Token has expired.'), 401);
    }

    // Still in time but has it been used before
    if (verify_service_time_stamp($domain, $timestamp, $nonce)) {
      return services_error(t('Token has been used previously for a request. Re-try with another nonce key.'), 401);
    }
    else{
      insert_service_timestamp($domain, $timestamp, $nonce);
    }

    $api_key = db_select('services_keys', 'sks')
    ->condition('kid', $key, '=')
    ->countQuery()
    ->execute()
    ->fetchAssoc();

    $domain_validate = db_select('services_keys', 'sks')
    ->fields('sks')
    ->condition('kid', $key, '=')
    ->execute()
    ->fetchAssoc();

     
    //check whether the key is available in database and the same
    if ( ($key != $settings['services_keyauth']) || $api_key['expression'] != 1) {
      return services_error(t('Invalid API key.'), 401);
    }
     
    //validate domain
    if ($domain_validate['domain'] != $domain) {
       
      return services_error(t('Invalid domain API key.'), 401);
    }
     
    //check whether the hashed value is fine
    if ($hash != services_get_hash($timestamp, $domain, $nonce, $key)) {
     return services_error(t('Invalid Hash key.'), 401);
    }

  }


}


/**
 * To check whether the key has been used alrady to prevent continous attack
 *
 * @param string $domain name
 * @param int $timestamp
 * @param String $nonce
 * @return boolean
 * 			true if it is available
 *          false if not
 */
function verify_service_time_stamp($domain, $timestamp, $nonce) {

  $verified_time_stamp = db_select('services_timestamp_nonce', 'sks')
  ->condition('domain', $domain, '=')
  ->condition('nonce', $nonce, '=')
  ->countQuery()
  ->execute()
  ->fetchAssoc();

  if ($verified_time_stamp['expression'])
  return TRUE;
  else
  return FALSE;
}


/**
 * Function to insert the service timestamp
 *
 * @param string $domain name
 * @param int $timestamp
 * @param String $nonce
 */
function insert_service_timestamp($domain, $timestamp, $nonce) {

  db_insert('services_timestamp_nonce')
  ->fields(array(
          'domain' => $domain,
          'nonce' => $nonce,
          'timestamp' => $timestamp,
  ))->execute();
}