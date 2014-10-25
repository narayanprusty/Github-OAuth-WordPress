<?php

session_start();

function apiRequest($url, $post=FALSE, $headers=array()) {
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
 
  if($post)
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
 
  $headers[] = 'Accept: application/json';
 
  if(session('access_token'))
    $headers[] = 'Authorization: Bearer ' . session('access_token');
 
  curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

  curl_setopt($ch, CURLOPT_USERAGENT, get_option("github_app_name")); 
 
  $response = curl_exec($ch);

  return json_decode($response);
}

function GithubApiRequest($url, $post=FALSE, $headers=array()) {
  $ch = curl_init($url);
  curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
 
  if($post)
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
 
  $headers[] = 'Accept: application/json';
 
  if(session('access_token'))
    $headers[] = 'Authorization: Bearer ' . get_user_meta(get_current_user_id(), "github_access_token", TRUE);
 
  curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

  curl_setopt($ch, CURLOPT_USERAGENT, get_option("github_app_name")); 
 
  $response = curl_exec($ch);

  return json_decode($response);
}

function generateRandomString($length = 10) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randomString = '';
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, strlen($characters) - 1)];
    }
    return $randomString;
} 

function get($key, $default=NULL) {
  return array_key_exists($key, $_GET) ? $_GET[$key] : $default;
}
 
function session($key, $default=NULL) {
  return array_key_exists($key, $_SESSION) ? $_SESSION[$key] : $default;
}

function github_oauth_redirect()
{
	global $wp, $wp_query, $wp_the_query, $wp_rewrite, $wp_did_header;
	require_once("../wp-load.php");

	$authorizeURL = 'https://github.com/login/oauth/authorize';
	$tokenURL = 'https://github.com/login/oauth/access_token';
	$apiURLBase = 'https://api.github.com/';

	define('OAUTH2_CLIENT_ID', get_option("github_key"));
	define('OAUTH2_CLIENT_SECRET', get_option("github_secret"));

	$_SESSION['state'] = hash('sha256', microtime(TRUE).rand().$_SERVER['REMOTE_ADDR']);
	unset($_SESSION['access_token']);
	$params = array(
    	'client_id' => OAUTH2_CLIENT_ID,
    	'redirect_uri' => get_site_url() . '/wp-admin/admin-ajax.php?action=github_oauth_callback',
    	'scope' => 'user',
    	'state' => $_SESSION['state']
  	);

  	header('Location: ' . $authorizeURL . '?' . http_build_query($params));

	die();
}

add_action("wp_ajax_github_oauth_redirect", "github_oauth_redirect");
add_action("wp_ajax_nopriv_github_oauth_redirect", "github_oauth_redirect");

function github_oauth_callback()
{
	global $wp, $wp_query, $wp_the_query, $wp_rewrite, $wp_did_header;
	require_once("../wp-load.php");

	$authorizeURL = 'https://github.com/login/oauth/authorize';
	$tokenURL = 'https://github.com/login/oauth/access_token';
	$apiURLBase = 'https://api.github.com/';

	define('OAUTH2_CLIENT_ID', get_option("github_key"));
	define('OAUTH2_CLIENT_SECRET', get_option("github_secret"));

	if(get('code')) {
  		if(!get('state') || $_SESSION['state'] != get('state')) {
    		header('Location: ' . $_SERVER['PHP_SELF']);
    		die();
  		}
  	}

  	$token = apiRequest($tokenURL, array(
	    'client_id' => OAUTH2_CLIENT_ID,
	    'client_secret' => OAUTH2_CLIENT_SECRET,
	    'redirect_uri' => get_site_url() . '/wp-admin/admin-ajax.php?action=github_oauth_callback',
	    'state' => $_SESSION['state'],
	    'code' => get('code')
  	));

 	$_SESSION['access_token'] = $token->access_token;


 	if(session('access_token')) 
 	{
	  	$user = apiRequest($apiURLBase . 'user');
	  	$email = $user->email;
	  	$username = $user->login;

	  	if(username_exists($username))
		{
			$user_id = username_exists($username);
			wp_set_auth_cookie($user_id);
			update_user_meta($user_id, "github_access_token", $_SESSION["access_token"]);
			header('Location: ' . get_site_url());
		}
		else
		{
			//create a new account and then login
			wp_create_user($username, generateRandomString(), $email);
			$user_id = username_exists($username);
			wp_set_auth_cookie($user_id);
			update_user_meta($user_id, "github_access_token", $_SESSION["access_token"]);
			header('Location: ' . get_site_url());
		}
 	}
 	else 
 	{
  		header('Location: ' . get_site_url());
  	}
	die();
}

add_action("wp_ajax_github_oauth_callback", "github_oauth_callback");
add_action("wp_ajax_nopriv_github_oauth_callback", "github_oauth_callback");
