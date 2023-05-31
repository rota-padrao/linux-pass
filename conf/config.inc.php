<?php
#==============================================================================
# Configuration
#==============================================================================

# Local password policy
# This is applied before directory password policy
# Minimal length
$pwd_min_length = 0;
# Maximal length
$pwd_max_length = 0;
# Minimal lower characters
$pwd_min_lower = 0;
# Minimal upper characters
$pwd_min_upper = 0;
# Minimal digit characters
$pwd_min_digit = 0;
# Minimal special characters
$pwd_min_special = 0;
# Definition of special characters
$pwd_special_chars = "^a-zA-Z0-9";
# Forbidden characters
#$pwd_forbidden_chars = "@%";
# Don't reuse the same password as currently
$pwd_no_reuse = true;
# Check that password is different than login
$pwd_diff_login = true;
# Complexity: number of different class of character required
$pwd_complexity = 0;

# Show policy constraints message:
# always
# never
# onerror
$pwd_show_policy = "onerror";

# root credentials
# for localhost leave $host = '';
$rootid = 'root';
$rootpass = 'root';
$host = '';

# Language
$lang ="pt-BR";

# Invalid characters in login
# If empty, only alphanumeric characters are accepted
$login_forbidden_chars = "*()&|";

?>
