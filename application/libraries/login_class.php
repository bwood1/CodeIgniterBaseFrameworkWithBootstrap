<?php

class Login {

    public static function loginLDAP($username, $password)
    {
        $ldap = self::connectLDAP();
        $loginValid = $ldap->authenticate($username, $password);

	    // $loginGroups = $ldap->user_groups($username);


        if ($loginValid)
        {

	    //$cookie_value = md5("boanpapbdiwobntolrfnq0930303l12".$username);
	    //$expire = (time()+(60*60));
	    //setcookie("cookie_hour", $cookie_value, $expire);

	    //$_SESSION['loggedin'] = strtolower($_POST['login_user']);
	    //$_SESSION['userGroup'] = $loginGroups;


	    //header('Content-Type: application/javascript');
	    //echo "yes";
	    //echo json_encode($a);

        }
        else
        {
	    //echo json_encode("error");

	    //header('Content-Type: application/javascript');
	    //echo "no";
	    //echo json_encode($a);
	    //die();
        }
        return $loginValid;
    }

    function set_up_faculty()
    {

    }

    public static function connectLDAP()
    {
        /*
		$ldapOptions = array(
			'account_suffix'	=> '@solitude.guc.usg.edu',
			'base_dn' 		=> 'ou=GGCNet,dc=solitude,dc=guc,dc=usg,dc=edu',
			'domain_controllers'	=> array('llyr.solitude.guc.usg.edu'),
			'use_tls'		=> true);
		*/
		$ldapOptions = array(
		    'account_suffix'		=> '@ggc.edu',
		    'base_dn' 			=> 'ou=GGCNet,dc=ggc,dc=edu',
		    'domain_controllers'	=> array('ldap.ggc.edu'),
		    'use_tls'		        => true
        );

		try
        {
            $ldap = new adLDAP($ldapOptions);

		}
        catch (adLDAPException $e)
        {
            echo $e;
            return false;
		}
	return $ldap;
    }

    function loginUser()
    {

		$ldapOptions = array(
		    'account_suffix'		=> '@solitude.guc.usg.edu',
		    'base_dn' 			=> 'ou=GGCNet,dc=solitude,dc=guc,dc=usg,dc=edu',
		    'domain_controllers'	=> array('llyr.solitude.guc.usg.edu')
                );
		$ldapOptions = array(
		    'account_suffix'		=> '@ggc.edu',
		    'base_dn' 			=> 'ou=GGCNet,dc=ggc,dc=edu',
		    'domain_controllers'	=> array('ldap.ggc.edu')
                );
		$ldap = new adLDAP($ldapOptions);

		if($ldap->authenticate($_POST['login_user'], self::decryptRSA($_POST['login_pass'])))  {
			$_SESSION['loggedInParking'] = strtolower($_POST['login_user']);


			// allow commenting
			$_SESSION['allowComments'] = true;

		} else {
			//print_r($_POST);
			//die("Invalid password / username combination.");
			header("location: index.php?error=1");
			die();
		}
	}

	function do_post_request($url, $data, $optional_headers = null)
    {
   $params = array('http' => array(
                  'method' => 'POST',
                  'content' => $data
               ));
     if ($optional_headers !== null) {
        $params['http']['header'] = $optional_headers;
     }
    $ctx = stream_context_create($params);
    $fp = fopen($url, 'rb', false, $ctx);
    if (!$fp) {
       throw new Exception("Problem with $url, $php_errormsg");
    }
    $response = stream_get_contents($fp);
    if ($response === false) {
       throw new Exception("Problem reading data from $url, $php_errormsg");
    }
    return $response;
   }

    function buildLogin()
    {
        if (isset($_SESSION['loggedInParking']))
        {
            header("location: home.php");
	} else
        {
            //$publicKey = self::getPublicRSAKey();
	    $publicKey['exponent']="";
	    $publicKey['modulus']="";


	    ?>

		<div id="public_key_exponent" style="display:none"><?php echo $publicKey['exponent'] ?></div>
		<div id="public_key_modulus" style="display:none"><?php echo $publicKey['modulus'] ?></div>
		<script src="/workshops/js/rsa/Barrett.js" type="text/javascript"></script>
		<script src="/workshops/js/rsa/BigInt.js" type="text/javascript"></script>
		<script src="/workshops/js/rsa/RSA.js" type="text/javascript"></script>
		<script src="/workshops/js/formencode.js" type="text/javascript"></script>

                <div class="centered_stuff">

                 <p>Please enter your GGC username and Password below: </p>

                <form method="POST" action="login_new.php" onsubmit="//return encode_field('password');">
                    <table border="0">
                        <tr>
                            <td align="right">
                                Username:
                            </td>
                            <td align="left">
                                <input type="text" name="login_user" size="15" />
                            </td>
                        </tr>
			<tr>
                            <td align="right">
                                Password:
                            </td>
                            <td>
                                <input type="password" name="login_pass" id="password" size="15" />
                            </td>
                        </tr>
                    </table>
		    <div>
                        <p>
                            <br />
                            <input type="submit" value="Login" />
                        </p>
                    </div>
                </div>
            <?php
        }
    }

   //RSA Login functions - error reporting suppressed as Crypt_RSA doesn't meet E_STRICT
   private static function decryptRSA($string) {
		$errorSettings = error_reporting(0);

		$pemString = file_get_contents('key.pem');

		$keyPair = Crypt_RSA_KeyPair::fromPEMString($pemString);

		$math_obj = &Crypt_RSA_MathLoader::loadWrapper('default');

		$rsa = new Crypt_RSA(array('dec_key' => $keyPair->getPrivateKey()));

		$cleartext = $rsa->decryptBinary($math_obj->int2bin($string));

		error_reporting($errorSettings);

		return $cleartext;
	}

	public static function getPublicRSAKey() {
		$errorSettings = error_reporting(0);

		$pemString = file_get_contents('key.pem');

		$keyPair = Crypt_RSA_KeyPair::fromPEMString($pemString);

		$math_obj = &Crypt_RSA_MathLoader::loadWrapper('default');

		$publicKey = $keyPair->getPublicKey();

		$keyArray = array(
			'exponent' 	=> $math_obj->bin2int($publicKey->getExponent()),
			'modulus'	=> $math_obj->bin2int($publicKey->getModulus()));

		if ($math_obj->getWrapperName() == 'GMP') {
			$keyArray = array_map('gmp_strval', $keyArray);
		}

		error_reporting($errorSettings);

		return $keyArray;
	}
}
