<?php
#==============================================================================
# Includes
#==============================================================================
require_once("conf/config.inc.php");
require_once("inc/functions.inc.php");

#==============================================================================
# Default values
#==============================================================================
if (!isset($pwd_forbidden_chars)) { $pwd_forbidden_chars = ""; }

# Password policy array
$pwd_policy_config = array(
    "pwd_show_policy"         => $pwd_show_policy,
    "pwd_min_length"          => $pwd_min_length,
    "pwd_max_length"          => $pwd_max_length,
    "pwd_min_lower"           => $pwd_min_lower,
    "pwd_min_upper"           => $pwd_min_upper,
    "pwd_min_digit"           => $pwd_min_digit,
    "pwd_min_special"         => $pwd_min_special,
    "pwd_special_chars"       => $pwd_special_chars,
    "pwd_forbidden_chars"     => $pwd_forbidden_chars,
    "pwd_no_reuse"            => $pwd_no_reuse,
    "pwd_diff_login"          => $pwd_diff_login,
    "pwd_complexity"          => $pwd_complexity
);

if (!isset($pwd_show_policy_pos)) { $pwd_show_policy_pos = "above"; }

#==============================================================================
# POST parameters
#==============================================================================
# Initiate vars
$result = "";
$login = "";
$oldpassword = "";
$newpassword = "";
$confirmpassword = "";


if (isset($_POST["confirmpassword"]) and $_POST["confirmpassword"]) { $confirmpassword = $_POST["confirmpassword"]; }
 else { $result = "confirmpasswordrequired"; }
if (isset($_POST["newpassword"]) and $_POST["newpassword"]) { $newpassword = $_POST["newpassword"]; }
 else { $result = "newpasswordrequired"; }
if (isset($_POST["oldpassword"]) and $_POST["oldpassword"]) { $oldpassword = $_POST["oldpassword"]; }
 else { $result = "oldpasswordrequired"; }
if (isset($_REQUEST["login"]) and $_REQUEST["login"]) { $login = $_REQUEST["login"]; }
 else { $result = "loginrequired"; }
if (! isset($_REQUEST["login"]) and ! isset($_POST["confirmpassword"]) and ! isset($_POST["newpassword"]) and ! isset($_POST["oldpassword"]))
 { $result = "emptychangeform"; }


# Check the entered username for characters that our installation doesn't support
if ( $result === "" ) {
    $result = check_username_validity($login,$login_forbidden_chars);
}

# Match new and confirm password
if ( $newpassword != $confirmpassword ) { $result="nomatch"; }


$shadow_cmd = "'grep -w root /etc/shadow | cut -d: -f2'";

$shadow_shell = passthru("sshpass -p root ssh root@localhost \"echo root | su -c 'grep -w root /etc/shadow | cut -d: -f2' - root\"");

echo $shadow_shell;

#==============================================================================
# Check old password
#==============================================================================
if ( $result === "" ) {

	$user_shadow = check_username($login);
	$salt = get_salt($user_shadow);
	$pass_shadow = crypt($oldpassword,$salt);

	if(!empty($user_shadow) && $user_shadow === $pass_shadow) {
		$result=""; }
	else { $result = "badcredentials"; }
}

#==============================================================================
# Check password strength
#==============================================================================
if ( $result === "" ) {
    $result = check_password_strength( $newpassword, $oldpassword, $pwd_policy_config, $login );
}

#==============================================================================
# Change password
#==============================================================================
if ( $result === "" ) {
    $result = change_password($login, $newpassword);
    if ( $result === "passwordchanged") {
        exec(escapeshellcmd("$login $newpassword $oldpassword"));
    }
}

#==============================================================================
# Lang
#==============================================================================
if (empty($lang)) { $lang = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2); }
require_once("lang/".$lang.".inc.php");

?>
  <!-- html form -->

<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title><?php echo $messages["title"]; ?></title>
  <!-- Tell the browser to be responsive to screen width -->
  <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">
  <!-- Bootstrap 3.3.7 -->
  <link rel="stylesheet" href="css/bootstrap.min.css">
  <!-- Font Awesome -->
  <link rel="stylesheet" href="css/font-awesome.min.css">
  <!-- Ionicons -->
  <link rel="stylesheet" href="css/ionicons.min.css">
  <!-- Theme style -->
  <link rel="stylesheet" href="css/pass.min.css">

  <!-- HTML5 Shim and Respond.js IE8 support of HTML5 elements and media queries -->
  <!-- WARNING: Respond.js doesn't work if you view the page via file:// -->
  <!--[if lt IE 9]>
  <script src="https://oss.maxcdn.com/html5shiv/3.7.3/html5shiv.min.js"></script>
  <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
  <![endif]-->

  <!-- Google Font -->
  <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Source+Sans+Pro:300,400,600,700,300italic,400italic,600italic">
</head>
<body class="hold-transition register-page">
<div class="register-box">
  <div class="register-logo">
    <a href=""><b><?php echo $messages["title"]; ?></b></a>
  </div>

  <div class="register-box-body">
    <div class="result alert alert-<?php echo get_criticity($result) ?>">
    <p><i class="fa <?php echo get_fa_class($result) ?>" aria-hidden="true"></i> <?php echo $messages[$result]; ?></p>
    </div>

    <?php
    if ($pwd_show_policy_pos === 'above') {
        show_policy($messages, $pwd_policy_config, $result);
    }
    ?>

    <form action="index.php" method="post">
      <div class="form-group has-feedback">
        <input type="text" name="login" id="login" class="form-control" placeholder="<?php echo $messages["login"]; ?>">
        <span class="glyphicon glyphicon-user form-control-feedback"></span>
      </div>
      <div class="form-group has-feedback">
        <input type="password" name="oldpassword" id="oldpassword" class="form-control" placeholder="<?php echo $messages["oldpassword"]; ?>">
        <span class="glyphicon glyphicon-lock form-control-feedback"></span>
      </div>
      <div class="form-group has-feedback">
        <input type="password" name="newpassword" id="newpassword" class="form-control" placeholder="<?php echo $messages["newpassword"]; ?>">
        <span class="glyphicon glyphicon-lock form-control-feedback"></span>
      </div>
      <div class="form-group has-feedback">
        <input type="password" name="confirmpassword" id="confirmpassword" class="form-control" placeholder="<?php echo $messages["confirmpassword"]; ?>">
        <span class="glyphicon glyphicon-log-in form-control-feedback"></span>
      </div>
      <div class="row">
        <div class="col-md-4 col-md-offset-4">
          <button type="submit" class="btn btn-primary btn-block btn-flat"><?php echo $messages['submit']; ?></button>
        </div>
        <!-- /.col -->
      </div>
    </form>

  </div>
  <!-- /.form-box -->
</div>
<!-- /.register-box -->

<script src="js/jquery-1.10.2.min.js"></script>
<script src="js/bootstrap.min.js"></script>

</body>
</html>
