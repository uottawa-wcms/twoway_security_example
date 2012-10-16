<?php

/**
 * This is an example of how to implement a security profile.
 *
 * Please do not use this class. As the implementation and security keys are
 * built in to this class, distributions that use it will be vulnerable. You
 * should create your own profile, using this one as a template.
 *
 * If you are looking for convienent salts or a way to send clear-text message
 * headers, you should use the $request->getMessageVar(key) and
 * $request->setMessageVar(key, value) methods. These allow you to work with
 * certain elements that will be sent in clear with the message and are therefore
 * good candidates for salts.
 *
 */
class TwoWaySecurityExampleProfile {

   /**
    * Called to secure the request upon creation.
    *
    * Recommended steps:
    * - Encrypt the password header
    * - Create a message ID message variable
    *
    * @param TwoWayRequest $request The request to secure
    */
  public function secureRequest(TwoWayRequest &$request) {
    $plaintext_password = $request->getHeader('password');
    // base64 is a terrible choice for encrypted passwords
    $encrypted = base64_encode($plaintext_password);
    $request->setHeader('password', $encrypted);
    // ideally, you should set a unique message code, then track which ones
    // you've received and make sure none are replayed.
    $message_id = '6';
    $request->setMessageVar('message_id', $message_id);
  }

  /**
    * Called to encrypt the outgoing message upon send.
    *
    * Recommended steps:
    * - Return an encrypted version of $compacted_message
    * - If you need to send a public key or IV of some kind, add a message variable
    *
    * @param string $compacted_message The compacted version of the message
    * @param TwoWayRequest $original The original request used to generate
    *   $compacted_message.
    * @return string The encrypted version of $compacted_message
    */
  public function encryptRequest($compacted_message, TwoWayRequest &$original) {
    // you should never use ECB mode.
    // you should also use a key that is not stored in code - store it in
    // a file and load it in just for this. adding a salt to your key based on
    // a getMessageVar() is also good.
    $encrypted = mcrypt_encrypt(
        MCRYPT_DES,
        'my_key',
        $compacted_message,
        MCRYPT_MODE_ECB
    );
    return $encrypted;
  }

  /**
   * Called to decrypt the incoming request.
   *
   * This is the reverse procedure from encryptRequest.
   *
   * @param string $compacted_message The encrypted message
   * @param array $vectors A list of unencrypted message headers.
   * @return string The decrypted message
   */
  public function decryptRequest($compacted_message, $vectors) {
    // reverse whatever you did in encryptRequest here.
    $decrypted = mcrypt_decrypt(
        MCRYPT_DES,
        'my_key',
        $compacted_message,
        MCRYPT_MODE_ECB
    );
    return trim($decrypted);
  }

  /**
    * Generates an HMAC based on the incoming compacted message.
    *
    * This operates on the non-encrypted version of the message.
    *
    * @param string $compacted_message The compacted version of the message.
    * @return string An HMAC for the message.
    */
  public function generateHMAC($compacted_message) {
    // md5 is not a good choice, especially not unsalted
    return md5($compacted_message);
  }

  /**
   * Examine the incoming message and see if it should be rejected.
   *
   * Ideally, this should examine the message headers and the information
   * stored in the request, and confirm that they are the same.
   *
   * @param TwoWayRequest $request The incoming request
   * @param array $vectors Message headers
   * @return boolean TRUE if the message should be rejected, otherwise FALSE.
   */
  public function invalidateRequest(TwoWayRequest &$request, $vectors) {
    // a simple example of validating the timestamps to make sure they are the
    // same. You can and should check many variables if you like.
    if ($request->getMessageVar('timestamp') != $vectors['timestamp']) {
      return TRUE;
    }
    return FALSE;
  }

  /**
   * This method reverses any security added in secureRequest.
   *
   * In this stage, you should decrypt the password field.
   *
   * You can save database-intensive operations for finalInvalidation.
   *
   * @param TwoWayRequest $request The incoming request
   */
  public function unsecureRequest(TwoWayRequest &$request) {
    // decrypting the password is important here, as this takes place
    // before the access check
    $request->setHeader('password', base64_decode($request->getHeader('password')));
  }

  /**
   * A second chance to reject the message, after it's been unsecured.
   *
   * In this stage, you should validate the message ID and make sure it's
   * valid.   *
   *
   * @param TwoWayRequest $request The incoming request
   * @return boolean TRUE if the message should be rejected, otherwise FALSE.
   */
  public function finalInvalidation(TwoWayRequest &$request) {
    // this is where we check the message ID, since it normally involves going
    // to the database.
    if ($request->getMessageVar('message_id') != '6') {
      return TRUE;
    }
    return FALSE;
  }

  /**
   * Allows the security profile to update the response headers before it's
   * sent.
   *
   * If you use a message ID, you can add it to the response object here.
   *
   * @param TwoWayResponse $response The response object.
   * @param TwoWayRequest $original_request The original request object.
   */
  public function prepareResponse(TwoWayResponse &$response, $original_request) {
    // let's send the same message ID back, for confirmation
    if (!empty($original_request)) {
      $response->setVector('message_id', $original_request->getMessageVar('message_id'));
    }
  }

  /**
   * Encrypts the response message.
   *
   * This should return an encrypted version of $compacted_message. If you need
   * to store an IV or a public key, you can include it in the response headers.
   *
   * @param string $compacted_message The unencrypted message text.
   * @param TwoWayResponse $original The original response object
   * @return string The encrypted message text
   */
  public function encryptResponse($compacted_message, TwoWayResponse &$original) {
    // lazy return encryption, do supply a better method
    return base64_encode($compacted_message);
  }

  /**
   * Decrypts the response message.
   *
   * This should reverse the operations done in encryptResponse.
   *
   * @param type $compacted_message
   * @param type $vectors
   * @return type
   */
  public function decryptResponse($compacted_message, $vectors) {
    return base64_decode($compacted_message);
  }

  /**
   * This allows you to replace which POST keys are used in the request.
   *
   * @param array $package The message package about to be sent
   * @return array The message package to actually send
   */
  public function obfuscateRequestPackage($package) {
    // let's just replace the keys to keep people guessing:
    $new_package = array(
      'fake_field1' => $package['package_verification'],
      'fake_field2' => $package['package_headers'],
      'encrypted_data' => md5(uniqid('')),
      'fake_field3' => $package['encrypted_package'],
    );
    return $new_package;
  }

  /**
   * Returns the POST keys of the request to their original state.
   *
   * Reverses the operation done in obfuscateRequestPackage.
   *
   * @param array $package The incoming message package
   * @return array The deobfuscated version of the message package
   */
  public function deobfuscateRequestPackage($package) {
    // reverse operations done before
    $actual_package = array(
      'package_verification' => $package['fake_field1'],
      'package_headers' => $package['fake_field2'],
      'encrypted_package' => $package['fake_field3'],
    );
    return $actual_package;
  }

  /**
   * Allows you to replace which POST keys are used in the response.
   *
   * @param array $package The message package about to be returned
   * @return array The message package to actually return
   */
  public function obfuscateResponsePackage($package) {
    // not going to touch it, see obfuscateRequestPackage for an example
    return $package;
  }

  /**
   * Returns the POST keys of the response to their original state.
   *
   * Reverse the operation done in obfuscateResponsePackage.
   *
   * @param array $package The message package that was received
   * @return array The actual message package
   */
  public function deobfuscateResponsePackage($package) {
    return $package;
  }

  /**
   * Encrypts a remote password, for storage in the database.
   *
   * @param string $password Plain-text password
   * @param array $vectors Variables that you can use to encrypt the password
   * @return string The encrypted password
   */
  public function encryptServerPassword($password, $vectors) {
    return base64_encode($password);
  }

  /**
   * Decrypts a remote password, from the database.
   *
   * @param string $password The encrypted password
   * @param array $vectors Variables that you can use to decrypt the password
   * @return string The plain-text password
   */
  public function decryptServerPassword($password, $vectors) {
    return base64_decode($password);
  }

  /**
   * Checks the response from the remote server to ensure it's valid.
   *
   * Should validate that the correct fields are present and that they match
   * the headers.
   *
   * @param TwoWayRemoteResponse $response The response object
   * @param array $vectors The original message headers
   * @return boolean TRUE if the fields are correct, otherwise FALSE.
   */
  public function validateResponse(TwoWayRemoteResponse $response, $vectors) {
    return $response->getVector('message_id') == '6';
  }




}

?>
