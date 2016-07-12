package Dancer2::Plugin::Auth::Extensible::Test::App;

=head1 NAME

Dancer2::Plugin::Auth::Extensible::Test::App - Dancer2 app for testing providers

=cut

our $VERSION = '0.601';

use strict;
use Dancer2 appname => 'TestApp';
use Dancer2::Plugin::Auth::Extensible;
use YAML ();
no warnings 'uninitialized';

set session => 'simple';
set logger => 'capture';
set log => 'debug';
set show_errors => 1;

get '/' => sub {
    "Index always accessible";
};

get '/loggedin' => require_login sub  {
    "You are logged in";
};

get '/name' => require_login sub {
    return "Hello, " . logged_in_user->{name};
};

get '/roles' => require_login sub {
    my $roles = user_roles() || [];
    return join ',', sort @$roles;
};

get '/roles/:user' => require_login sub {
    my $user = param 'user';
    return join ',', sort @{ user_roles($user) };
};

get '/roles/:user/:realm' => require_login sub {
    my $user = param 'user';
    my $realm = param 'realm';
    return join ',', sort @{ user_roles($user, $realm) };
};

get '/realm' => require_login sub {
    return session->read('logged_in_user_realm');
};

get '/beer' => require_role BeerDrinker => sub {
    "You can have a beer";
};

get '/cider' => require_role CiderDrinker => sub {
    "You can have a cider";
};

get '/piss' => require_role BearGrylls => sub {
    "You can drink piss";
};

get '/piss/regex' => require_role qr/beer/i => sub {
    "You can drink piss now";
};

get '/anyrole' => require_any_role ['Foo','BeerDrinker'] => sub {
    "Matching one of multiple roles works";
};

get '/allroles' => require_all_roles ['BeerDrinker', 'Motorcyclist'] => sub {
    "Matching multiple required roles works";
};

get '/not_allroles' => require_all_roles ['BeerDrinker', 'BadRole'] => sub {
    "Matching multiple required roles should fail";
};

get qr{/regex/(.+)} => require_login sub {
    return "Matched";
};

get '/require_login_no_sub' => require_login;

get '/require_login_not_coderef' => require_login { a => 1 };

get '/does_dave_drink_beer' => sub {
    return user_has_role('dave', 'BeerDrinker');
};

get '/does_dave_drink_cider' => sub {
    return user_has_role('dave', 'CiderDrinker');
};

get '/does_undef_drink_beer' => sub {
    return user_has_role(undef, 'BeerDrinker');
};

get '/authenticate_user_with_realm_pass' => sub {
    return authenticate_user('dave', 'beer', 'config1');
};

get '/authenticate_user_with_realm_fail' => sub {
    return authenticate_user('dave', 'cider', 'config1');
};

get '/authenticate_user_with_wrong_realm' => sub {
    return authenticate_user('dave', 'beer', 'config2');
};

get '/user_password' => sub {
    return user_password params('query');
};

get '/create_user/:realm' => sub {
    my $realm = param 'realm';
    create_user username => 'newuser', realm => $realm;
    user_password username => 'newuser', realm => $realm, new_password => "pish_$realm";
};

get '/update_current_user' => sub {
    update_current_user name => "I love cider";
};

get '/update_user_name/:realm' => sub {
    my $realm = param 'realm';
    update_user 'mark', realm => $realm, name => "Wiltshire Apples $realm";
};

get '/update_user_role/:realm' => sub {
    my $realm = param 'realm';
    update_user 'mark', realm => $realm, role => { CiderDrinker => 1 };
};

get '/get_user_mark/:realm' => sub {
    my $realm = param 'realm';
    content_type 'text/x-yaml';
    YAML::Dump get_user_details 'mark', $realm;
};


1;
