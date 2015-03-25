<?php

/*
  See this link for additional info on howto create an extension
 * https://wiki.phpbb.com/Authentication_providers

 The following link is somewhat outdated, but the return values are still valid
 * https://wiki.phpbb.com/Authentication_plugins
 phpBBroot/includes/constants.php
 contains the defined constants used below.
 */

namespace loki\login\auth\provider;

if (!defined('IN_PHPBB')) {
  echo "error";
  exit;
}

class loki_auth extends \phpbb\auth\provider\base
{



   function quoteIMAP($str)
    {
        return @ereg_replace('(["\\])', '\\\\1', $str);
    }

  /**
   * Database Authentication Constructor
   *
   * @param    \phpbb\db\driver\driver_interface    $db
   */
  public function __construct(\phpbb\db\driver\driver_interface $db)
         {
           $this->db = $db;
         }

  /**
   * {@inheritdoc}
   */
  public function login($username, $password)
         {
           // Auth plugins get the password untrimmed.
           // For compatibility we trim() here.
           $password = trim($password);

           // do not allow empty password
           if (!$password)
           {
             return array(
                 'status'    => LOGIN_ERROR_PASSWORD,
                 'error_msg'    => 'NO_PASSWORD_SUPPLIED',
                 'user_row'    => array('user_id' => ANONYMOUS),
                          );
           }

           if (!$username)
           {
             return array(
                 'status'    => LOGIN_ERROR_USERNAME,
                 'error_msg'    => 'LOGIN_ERROR_USERNAME',
                 'user_row'    => array('user_id' => ANONYMOUS),
                          );
           }
           $username_clean = utf8_clean_string($username);

           $error_number = "";
           $error_string = "";

           // Connect to IMAP-server
           $stream = fsockopen( mail, 143, $error_number, $error_string, 15 )
               or die("Could not connect to IMAP server: $error_string");
           $response = fgets( $stream, 1024 );
           if( $stream ) {
             $logon_str = "a001 LOGIN \"" . $this->quoteIMAP( $username_clean ) .
                 "\" \"" . $this->quoteIMAP( $password ) . "\"\r\n";
             fputs( $stream, $logon_str );
             $response = fgets( $stream, 1024 );
             if( substr( $response, 5, 2 ) == 'OK' ) {
               fputs( $stream, "a001 LOGOUT\r\n" );
               $response = fgets( $stream, 1024 );
               $login = true;
             }
             fputs( $stream, "a001 LOGOUT\r\n" );
           }

           if ( $login){
             // Successful login
             // If user doesn't exist in phpBB db, then create profile
             // otherwise just send LOGIN_SUCCESS

             // sgdb inquiry
             require(__DIR__ . '/../../../../../../include/forum_mysqlconn.inc.php');
             $sgdbQuery = "select * from user where user = '" . $username_clean . "';";
             $sgdbResult = mysqli_query($dbLink, $sgdbQuery);
             $sgdbRow = mysqli_fetch_array($sgdbResult);
             mysqli_close($dbLink);

             // phpBB inquiry
             $phpbbQuery = "select 1 from phpbb_users where user_id = ". $sgdbRow['user_id'];
             $phpbbResult = $this->db->sql_query($phpbbQuery);
             $phpbbRow = $this->db->sql_fetchrow($phpbbResult);
             $this->db->sql_freeresult($result);

             $row = array(
                 'user_id' => $sgdbRow['user_id'],
                 'username' => $username_clean,
                 'user_password' => phpbb_hash($password),
                 'user_email' => $username_clean . '@studentergaarden.dk',
                 'user_login_attempts' => '0',
                 'group_id' => (int) 2, // 2: normal user, 4: moderator, 5: admin
                 'user_type' => USER_NORMAL,
                          );
             if ($phpbbRow){ // user exist in phpBB db
               return array(
                   'status'      => LOGIN_SUCCESS,
                   'error_msg'   => false,
                   'user_row'    => $row,
                            );
             }else{ // create user in phpBB
               return array(
                   'status'      => LOGIN_SUCCESS_CREATE_PROFILE,
                   'error_msg'   => false,
                   'user_row'    => $row,
                            );
             }
           }else{ // IMAP login failed
             return array(
                 'status' => LOGIN_ERROR_USERNAME,
                 'error_msg' => 'LOGIN_ERROR_USERNAME',
                 'user_row'    => array('user_id' => ANONYMOUS),
                          );
           }
         }
}