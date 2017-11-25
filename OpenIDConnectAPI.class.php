<?php
const BEARER_TOKEN_PREFIX = 'Bearer ';

require_once('/usr/share/php/rmccue/Requests/Requests.php');
Requests::register_autoloader();


class OpenIDConnectAPI {
    public static function beforeAPIMain( &$main ) {
        if(array_key_exists("HTTP_AUTHORIZATION", $_SERVER)) {
            $authz = $_SERVER["HTTP_AUTHORIZATION"];
            if(substr($authz, 0, strlen(BEARER_TOKEN_PREFIX)) === BEARER_TOKEN_PREFIX) {
                $authz = substr($authz, strlen(BEARER_TOKEN_PREFIX));

                $username = OpenIDConnectAPI::checkApiToken($authz);
                if($username === false) {
                    http_response_code(401);
                    die('Auth error');
                }

                $uid = $main->getContext()->getUser()->idFromName($username);
                if(is_null($uid)) {
                    http_response_code(401);
                    die('Unknown user');
                }

                $main->getContext()->getUser()->mId = $uid;
                $main->getContext()->getUser()->loadFromID();
                $main->getContext()->getRequest()->getSession()->set('wsTokenSecrets', array('default' => $authz));
            }
        }
    }

    static function checkApiToken($token) {
        $iss = $GLOBALS['wgOpenIDConnectAPI_Issuer'];
        if ( !isset( $GLOBALS['wgOpenIDConnectAPI_TokenScope'] ) ) {
            wfDebug("OpenID Connect API: misconfigured");
            return false;
        }
        $scope = $GLOBALS['wgOpenIDConnectAPI_TokenScope'];
        if ( !isset( $GLOBALS['wgOpenIDConnectAPI_TokenInfoURL'] ) ) {
            wfDebug("OpenID Connect API: misconfigured");
            return false;
        }
        $tokenurl = $GLOBALS['wgOpenIDConnectAPI_TokenInfoURL'];
        if ( !isset( $GLOBALS['wgOpenIDConnect_Config'][$iss] ) ) {
            wfDebug("OpenID Connect API: misconfigured");
            return false;
        }
        $config = $GLOBALS['wgOpenIDConnect_Config'][$iss];
        if ( !isset( $config['clientID'] ) || !isset( $config['clientsecret'] ) ) {
            wfDebug("OpenID Connect API: misconfigured");
            return false;
        }
        $clientid = $config['clientID'];
        $clientsecret = $config['clientsecret'];

        $options = array(
            'auth' => new Requests_Auth_Basic(array($clientid, $clientsecret))
        );
        $data = array(
            'token_type_hint' => 'access_token',
            'token' => $token
        );

        $response = Requests::post($tokenurl, array(), $data, $options);

        if(!$response->success) {
            http_response_code(401);
            die('Invalid token');
        }
        $decoded = json_decode($response->body);

        if($decoded->{'active'} !== true) {
            http_response_code(401);
            die('Invalid token');
        }
        $scopes = explode(' ', $decoded->{'scope'});

        if(!in_array($scope, $scopes)) {
            http_response_code(401);
            die('Invalid token');
        }

        return $decoded->{'username'};
    }
}
?>
