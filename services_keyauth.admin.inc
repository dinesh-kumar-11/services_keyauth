<?php
// $Id: services_keyauth.admin.inc,v 1.1.2.2.2.7 2010/02/26 17:32:33 heyrocker Exp $

/**
 * @file
 *  Generate security keys.
 */

/**
 * Display all the available API keys.
 */
function services_keyauth_admin_keys_list() {
  $keys = services_keyauth_get_keys();
  $header = array(t('Key'), t('Title'), t('Domain'), array('data' => t('Operations'), 'colspan' => '2'));
  $rows = array();

  foreach ($keys as $kid => $key) {
    $row = array();

    $row[] = $key['service_key'];
    $row[] = $key['title'];
    $row[] = l(t('list domains'), 'admin/connect/services/keys/list/domains/' . $kid);

    // Populate the operations field.
    $operations = array();

    // Set the edit column.
    $operations[] = array('data' => l(t('edit'), 'admin/connect/services/keys/' . $kid));

    // Set the delete column.
    $operations[] = array('data' => l(t('delete'), 'admin/connect/services/keys/' . $kid . '/delete'));

    foreach ($operations as $operation) {
      $row[] = $operation;
    }
    $rows[] = $row;
  }

  if (empty($rows)) {
    $rows[] = array(array('data' => t('No API keys created.'), 'colspan' => '5', 'class' => 'message'));
  }
  $variables['header'] = $header;
  $variables['rows'] = $rows;

  return theme('table', $variables);
}

/**
 * Display the form to create or edit API keys.
 */
function services_keyauth_admin_keys_form() {
  $kid = arg(4);

  $key = db_select('services_keys', 'sks')
    ->fields('sks')
    ->condition('kid', $kid, '=')
    ->execute()
    ->fetchAssoc();
  $key_domain = db_select('services_key_domain', 'sks')
    ->fields('sks')
    ->condition('kid', $kid, '=')
    ->execute()
    ->fetchAllAssoc('domain_id');

  $key_domain = array_keys($key_domain);

  $key_kid = isset($key['kid']) ? $key['kid'] : '';
  $key_title = isset($key['title']) ? $key['title'] : '';
  $form['kid'] = array(
    '#type'           => 'hidden',
    '#default_value'  => $key_kid,
  );

  $domain_vocab = taxonomy_vocabulary_machine_name_load(DOMAINS_VOCAB);

  $domain_term_list = taxonomy_get_tree($domain_vocab->vid);

  $domain_arr = array();
  foreach ($domain_term_list as $domain) {
    $domain_arr[$domain->tid] = $domain->name;
  }

  $accessible_methods = array();
  if ($key_kid != '') {
    $form['key'] = array(
      '#type'           => 'markup',
      '#title'          => t('Key'),
      '#value'          => '<strong>' . t('API Key') . ':</strong> ' . $key_kid,
    );
  }

  $form['title'] = array(
    '#title'          => t('Application title'),
    '#type'           => 'textfield',
    '#default_value'  => $key_title,
    '#description'    => t('The title of the application or website using the service.'),
    '#required'       => TRUE,
  );

  $form['domain'] = array(
    '#type' => 'select',
    '#title' => t('Domain'),
    '#description' => t('Select Domain, Use ctrl key to select multiple domains'),
    '#multiple' => TRUE,
    '#options' => $domain_arr,
    '#size' => min(8, count($domain_arr)),
    '#default_value' => !empty($key_domain) ? $key_domain : '',
  );

  $form['submit'] = array(
    '#type'           => 'submit',
    '#value'          => $key_title != '' ? t('Save key') : t('Create key'),
  );

  $form['#validate'][] = 'services_keyauth_admin_keys_form_validate';

  return $form;
}

/**
 * Submit callback for services_keyauth_admin_keys_form().
 */
function services_keyauth_admin_keys_form_validate($form, &$form_state) {
  $domain_id = $form_state['values']['domain'];

  // patch for setting up multiple key for the root.
  global $_domain;

  $vocab = taxonomy_vocabulary_machine_name_load(DOMAINS_VOCAB);
  $self_term = taxonomy_get_term_by_name($_domain['subdomain'], $vocab->machine_name);
  $self_term = array_pop($self_term);
  unset($domain_id[$self_term->tid]);


  if (!empty($form_state['values']['kid']) && $domain_id) {
    $get_kid = db_select('services_key_domain', 'sks')
      ->fields('sks', array('kid'))
      ->condition('domain_id', $domain_id, 'IN')
      ->execute()
      ->fetchfield();
    if ($get_kid != $form_state['values']['kid'] && $get_kid !== FALSE) {
      form_set_error('domain', 'One of the Domains selected is already mapped to another key.Please remove association with previsous key.');
    }
  }

  if (empty($form_state['values']['kid']) && $domain_id) {
    $get_kid = db_select('services_key_domain', 'sks')
      ->fields('sks', array('kid'))
      ->condition('domain_id', $domain_id, 'IN')
      ->execute()
      ->fetchfield();
    if ($get_kid) {
      form_set_error('domain', 'One of the Domains selected is already mapped to another key.Please remove association with previsous key.');
    }
  }

}

/**
 * Submit callback for services_keyauth_admin_keys_form().
 */
function services_keyauth_admin_keys_form_submit($form, &$form_state) {
  services_keyauth_admin_keys_save($form_state['values']);
  cache_clear_all('services', 'cache', TRUE);
  cache_clear_service_auth();
  $form_state['redirect']  =  'admin/connect/services/keys';
}

/**
 * Save an API key.
 *
 * @param $key
 *   Associative array containing API key information.
 *
 * @return
 *   A constant, either SAVED_NEW or SAVED_UDPATED.
 */
function services_keyauth_admin_keys_save(&$key) {
  $transaction = db_transaction();
  try {
    $is_existing = FALSE;
    if (!empty($key['kid'])) {
      $is_existing =   db_select('services_keys', 'sks')
        ->fields('sks', array('kid', 'service_key'))
        ->condition('kid', $key['kid'], '=')
        ->execute()
        ->fetchallKeyed();
    }
    $key['service_key'] = ($is_existing) ? $is_existing[$key['kid']] : md5(uniqid(mt_rand(), TRUE));

    if ($is_existing) {
      db_delete('services_key_domain') // Table name no longer needs {}
        ->condition('kid', $key['kid'], '=')
        ->execute();
      db_update('services_keys')
        ->fields(array('title' => $key['title']))
        ->condition('kid', $key['kid'], '=')
        ->execute();
      $return = SAVED_UPDATED;
      drupal_set_message(t('A Key has been sucessfully update'));
    }
    else {
      $insert_object =  db_insert('services_keys')
        ->fields(array(
          'service_key' => $key['service_key'],
          'title' => $key['title'],
        ))
        ->execute();
      $key['kid'] = $insert_object;
    }

    if (is_array($key['domain']) && !empty($key['domain']) && $key['kid']) {
      foreach ($key['domain'] as $domain_id) {
        db_insert('services_key_domain')
          ->fields(array(
            'kid' => $key['kid'],
            'domain_id' => $domain_id,
          ))
          ->execute();
      }
    }

    if (!$is_existing) {
      $return = SAVED_NEW;
      drupal_set_message(t('A Key has been sucessfully created'));
    }
    cache_clear_service_auth();
  }
  catch (Exception $e) {
    $transaction->rollback();
    watchdog_exception('services keys', $e);
    throw $e;
  }
  return $return;
}

/**
 * Delete an API key.
 *
 * @param $kid
 *   Unique identifier from the services_keys table.
 */
function services_keyauth_admin_keys_delete($kid) {
  db_delete('services_keys')
    ->condition('kid', $kid)
    ->execute();
  db_delete('services_key_domain')
    ->condition('kid', $kid)
    ->execute();
  cache_clear_service_auth();
}

/**
 * Show a form to confirm whether an API key should be deleted.
 */
function services_keyauth_admin_keys_delete_confirm($form, $form_state, $kid = 0) {

  $key = db_select('services_keys', 'sks')
    ->fields('sks', array('kid', 'service_key'))
    ->condition('kid', $kid, '=')
    ->execute()
    ->fetchallKeyed();

  $form['kid'] = array('#type' => 'value', '#value' => $kid);

  $message = t('Are you sure you want to delete the key %key?', array('%key' => $key[$kid]));
  $caption = '';

  $caption .= '<p>' . t('This action cannot be undone.') . '</p>';

  return confirm_form($form, filter_xss($message), 'admin/connect/services/keys', filter_xss($caption), t('Delete'));
}

/**
 * Submit form callback for services_keyauth_admin_keys_delete_confirm().
 */
function services_keyauth_admin_keys_delete_confirm_submit($form, &$form_state) {
  services_keyauth_admin_keys_delete($form_state['values']['kid']);

  $t_args = array('%key' => $form_state['values']['kid']);
  drupal_set_message(t('The key %key has been deleted.', $t_args));
  watchdog('services_key', 'Deleted key %key.', $t_args, WATCHDOG_NOTICE);

  $form_state['redirect'] = 'admin/connect/services/keys';
}



/** 
 * Implementation of hook_form()
 *
 */
function services_key_admin_keys_list($kid) {
  if (empty($kid)) {
    drupal_goto('admin/connect/services/keys');
    return;
  }

  $key = db_select('services_keys', 'sks')
    ->fields('sks')
    ->condition('kid', $kid, '=')
    ->execute()
    ->fetchAssoc();
  $key_domain = db_select('services_key_domain', 'sks')
    ->fields('sks')
    ->condition('kid', $kid, '=')
    ->execute()
    ->fetchAllAssoc('domain_id');

  $domains = taxonomy_term_load_multiple(array_keys($key_domain));

  $domain_list = array();
  foreach ($domains as $tid => $term_object) {
    $domain_list[] = $term_object->name . ' [' . $tid . ']';
  }


  $rows = array(
    array(
      array('data' => t('Key'), 'header' => TRUE),
      $key['service_key'],
    ),
    array(
      array('data' => t('Title'), 'header' => TRUE),
      $key['title'] . l(t('[Edit]'), 'admin/connect/services/keys/' . $kid),
    ),
    array(
      array('data' => t('Domains'), 'header' => TRUE),
      theme('item_list', array('items' => $domain_list)),
    ),
  );
  $build['dblog_table'] = array(
    '#theme' => 'table',
    '#rows' => $rows,
    '#attributes' => array('class' => array('dblog-event')),
  );

  return $build;

}