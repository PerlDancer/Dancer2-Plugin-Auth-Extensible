package Dancer2::Plugin::Auth::Extensible::Test::App;

=head1 NAME

Dancer2::Plugin::Auth::Extensible::Test::App - Dancer2 app for testing providers

=cut

our $VERSION = '0.614';

use strict;
use warnings;
use Test::More;
use Test::Deep qw(bag cmp_deeply);
use Test::Fatal;
use Dancer2 appname => 'TestApp';
use Dancer2::Plugin::Auth::Extensible;
use Scalar::Util qw(blessed);
use YAML ();

set session => 'simple';
set logger => 'capture';
set log => 'debug';
set show_errors => 1;

# nasty shared global makes it easy to pass data between app and test script
our $data = {};

config->{plugins}->{"Auth::Extensible"}->{reset_password_handler} = 1;
config->{plugins}->{"Auth::Extensible"}->{welcome_send} =
  __PACKAGE__ . "::welcome_send";

sub welcome_send {
    my ( $plugin, %args ) = @_;
    $data = \%args;
}

# we need the plugin object and a provider for provider tests
my $plugin = app->with_plugin('Auth::Extensible');
my $provider = $plugin->auth_provider('config1');

my @provider_can = ();

subtest 'Provider authenticate_user tests' => sub {
    my $ret;
    push @provider_can, 'authenticate_user';

    like exception { $ret = $provider->authenticate_user(); },
      qr/username and password must be defined/,
      "authenticate_user with no args dies.";

    like exception { $ret = $provider->authenticate_user(''); },
      qr/username and password must be defined/,
      "authenticate_user with empty username and no password dies.";

    like exception { $ret = $provider->authenticate_user(undef, ''); },
      qr/username and password must be defined/,
      "authenticate_user with undef username and empty password dies.";

    is exception { $ret = $provider->authenticate_user('', ''); },
      undef,
      "authenticate_user with empty username and empty password lives.";
    ok !$ret, "... and returns a false value.";

    is exception { $ret = $provider->authenticate_user('unknown', 'beer'); },
      undef,
      "authenticate_user with unknown user lives.";
    ok !$ret, "... and returns a false value.";

    is exception { $ret = $provider->authenticate_user('dave', 'notcorrect'); },
      undef,
      "authenticate_user with known user and bad password lives.";
    ok !$ret, "... and returns a false value.";

    is exception { $ret = $provider->authenticate_user('dave', 'beer'); },
      undef,
      "authenticate_user with known user and good password.";
    ok $ret, "... and returns a true value.";
};

SKIP: {
    skip "Provider has no get_user_details method", 1
      unless $provider->can('get_user_details');

    subtest 'Provider get_user_details tests' => sub {
        my $ret;

        push @provider_can, 'get_user_details';

        like exception { $ret = $provider->get_user_details(); },
          qr/username must be defined/,
          "get_user_details with no args dies.";

        is exception { $ret = $provider->get_user_details(''); },
          undef,
          "get_user_details with empty username lives.";
        ok !$ret, "... and returns a false value.";

        is exception { $ret = $provider->get_user_details('unknown'); },
          undef,
          "get_user_details with unknown user lives.";
        ok !$ret, "... and returns a false value.";

        is exception { $ret = $provider->get_user_details('dave'); },
          undef,
          "get_user_details with known user lives.";
        ok $ret, "... and returns a true value";
        ok blessed($ret) || ref($ret) eq 'HASH',
          "... which is either an object or a hash reference"
          or diag explain $ret;
        is blessed($ret) ? $ret->name : $ret->{name}, 'David Precious',
          "... and user's name is David Precious.";
    };
}

SKIP: {
    skip "Provider has no get_user_roles method", 1
      unless $provider->can('get_user_roles');

    subtest 'Provider get_user_roles tests' => sub {
        my $ret;

        push @provider_can, 'get_user_roles';

        like exception { $ret = $provider->get_user_roles(); },
          qr/username must be defined/,
          "get_user_roles with no args dies.";

        is exception { $ret = $provider->get_user_roles(''); }, undef,
          "get_user_roles with empty username lives";
        ok !$ret, "... and returns false value.";

        is exception { $ret = $provider->get_user_roles('unknown'); }, undef,
          "get_user_roles with unknown user lives";
        ok !$ret, "... and returns false value.";

        is exception { $ret = $provider->get_user_roles('dave'); }, undef,
          "get_user_roles with known user \"dave\" lives";
        ok $ret, "... and returns true value";
        is ref($ret), 'ARRAY', "... which is an array reference";
        cmp_deeply $ret, bag( "BeerDrinker", "Motorcyclist" ),
          "... and dave is a BeerDrinker and Motorcyclist.";
    };
}

SKIP: {
    skip "Provider has no create_user method", 1
      unless $provider->can('create_user');

    subtest 'Provider create_user tests' => sub {
        my $ret;

        push @provider_can, 'create_user';

        like exception { $ret = $provider->create_user(); },
          qr/username not supplied in args/i,
          "create_user with no args dies.";

        like exception { $ret = $provider->create_user(username => ''); },
          qr/username not supplied in args/i,
          "create_user with empty username dies.";

        like exception { $ret = $provider->create_user(username => 'dave'); },
          qr/user already exists|constraint/i,
          "create_user with existing username dies.";

        is exception {
            $ret = $provider->get_user_details('provider_create_user');
        },
          undef,
          "get_user_details \"provider_create_user\" lives";
        ok !defined $ret, "... and does not return a user.";

        is exception {
            $ret = $provider->create_user(
                username => 'provider_create_user',
                name     => 'Create User'
            );
        },
          undef,
          "create_user \"provider_create_user\" lives";

        ok defined $ret, "... and returns a user";
        is blessed($ret) ? $ret->name : $ret->{name}, "Create User",
          "... and user's name is correct.";

        is exception {
            $ret = $provider->get_user_details('provider_create_user');
        },
          undef,
          "get_user_details \"provider_create_user\" lives";
        ok defined $ret, "... and now *does* return a user.";
        is blessed($ret) ? $ret->name : $ret->{name}, "Create User",
          "... and user's name is correct.";
    };
}

SKIP: {
    skip "Provider has no set_user_details method", 1
      unless $provider->can('set_user_details');

    subtest 'Provider set_user_details tests' => sub {
        my $ret;

        push @provider_can, 'set_user_details';

        like exception { $ret = $provider->set_user_details(); },
          qr/username to update needs to be specified/i,
          "set_user_details with no args dies.";

        like exception { $ret = $provider->set_user_details(''); },
          qr/username to update needs to be specified/i,
          "set_user_details with empty username dies.";

        is exception {
            $ret = $provider->create_user(
                username => 'provider_set_user_details',
                name     => 'Initial Name'
            );
        },
          undef,
          "Create a user for testing lives";

        is exception {
            $ret = $provider->get_user_details('provider_set_user_details')
        },
          undef,
          "... and get_user_details on new user lives";

        is blessed($ret) ? $ret->name : $ret->{name}, 'Initial Name',
          "... and user has expected name.";

        is exception {
            $ret = $provider->set_user_details( 'provider_set_user_details',
                name => 'New Name', );
        },
          undef,
          "Using set_user_details to change user's name lives";

        is blessed($ret) ? $ret->name : $ret->{name}, 'New Name',
          "... and returned user has expected name.";

        is exception {
            $ret = $provider->get_user_details('provider_set_user_details')
        },
          undef,
          "... and get_user_details on new user lives";

        is blessed($ret) ? $ret->name : $ret->{name}, 'New Name',
          "... and returned user has expected name.";
    };
}

SKIP: {
    skip "Provider has no get_user_by_code method", 1
      unless $provider->can('get_user_by_code');

    subtest 'Provider get_user_by_code tests' => sub {
        my $ret;

        push @provider_can, 'get_user_by_code';

        like exception { $ret = $provider->get_user_by_code(); },
          qr/code needs to be specified/i,
          "get_user_by_code with no args dies.";

        like exception { $ret = $provider->get_user_by_code(''); },
          qr/code needs to be specified/i,
          "get_user_by_code with empty code dies.";

        is exception { $ret = $provider->get_user_by_code('nosuchcode'); },
          undef,
          "get_user_by_code with non-existant code lives";
        ok !defined $ret, "... and returns undef.";

        is exception {
            $ret = $provider->create_user(
                username      => 'provider_get_user_by_code',
                pw_reset_code => '01234567890get_user_by_code',
            );
        },
          undef,
          "Create a user for testing lives";

        is exception {
            $ret = $provider->get_user_by_code('01234567890get_user_by_code');
        },
          undef,
          "get_user_by_code with non-existant code lives";
        ok defined $ret, "... and returns something true";

        is $ret, 'provider_get_user_by_code',
          "... and returned username is correct.";
    };
}

SKIP: {
    skip "Provider has no set_user_password method", 1
      unless $provider->can('set_user_password');

    subtest 'Provider set_user_password tests' => sub {
        my $ret;

        push @provider_can, 'set_user_password';

        like exception { $ret = $provider->set_user_password(); },
          qr/username and password must be defined/i,
          "set_user_password with no args dies.";

        like exception { $ret = $provider->set_user_password(''); },
          qr/username and password must be defined/i,
          "set_user_password with username but undef password dies";

        like exception { $ret = $provider->set_user_password( undef, '' ); },
          qr/username and password must be defined/i,
          "set_user_password with password but undef username dies";

        is exception {
            $ret =
              $provider->create_user( username => 'provider_set_user_password' )
        },
          undef,
          "Create a user for testing lives";

        is exception {
            $ret = $provider->set_user_password( 'provider_set_user_password',
                'aNicePassword' )
        },
        undef, "set_user_password for our new user lives";

        is exception {
            $ret = $provider->authenticate_user( 'provider_set_user_password',
                'aNicePassword' )
        },
        undef, "... and authenticate_user with correct password lives";
        ok $ret, "... and authenticate_user passes (returns true)";

        is exception {
            $ret = $provider->authenticate_user( 'provider_set_user_password',
                'badpwd' )
        },
        undef, "... and whilst authenticate_user with bad password lives";
        ok !$ret, "... it returns false.";
    };
}

SKIP: {
    skip "Provider has no password_expired method", 1
      unless $provider->can('password_expired');

    subtest 'Provider password_expired tests' => sub {
        my $ret;

        push @provider_can, 'password_expired';

        like exception { $ret = $provider->password_expired(); },
          qr/user must be specified/i,
          "password_expired with no args dies.";

        is exception {
            $ret =
              $provider->create_user( username => 'provider_password_expired' )
        },
          undef,
          "Create a user for testing lives";

        is exception {
            $ret = $provider->password_expired($ret)
        },
          undef,
          "... and password_expired for user lives";

        ok $ret, "... and password is expired since it has never been set.";

        is exception {
            $ret = $provider->set_user_password( 'provider_password_expired',
                'password' )
        },
          undef,
          "Setting password for user lives";

        is exception {
            $ret = $provider->password_expired($ret)
        },
          undef,
          "... and password_expired for user lives";

        ok !$ret, "... and password is now *not* expired.";

        is exception {
            $ret = $provider->set_user_details( 'provider_password_expired',
                pw_changed => DateTime->now->subtract( weeks => 1 ) )
        },
          undef,
          "Set pw_changed to one week ago lives and so now password is expired";

        is exception {
            $ret = $provider->password_expired($ret)
        },
          undef,
          "... and password_expired for user lives";

        ok $ret, "... and password *is* now expired since expiry is 2 days.";

    };
}


get '/provider_can' => sub {
    send_as YAML => \@provider_can;
};

get '/' => sub {
    "Index always accessible";
};

get '/loggedin' => require_login sub  {
    "You are logged in";
};

get '/name' => require_login sub {
    my $user = logged_in_user;
    my $name = blessed($user) ? logged_in_user->name : logged_in_user->{name};
    return "Hello, $name";
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

post '/create_user' => sub {
    my $params   = body_parameters->as_hashref;
    my $password = delete $params->{password};
    my $user     = create_user %$params;
    if ( $user && $password ) {
        user_password
          username     => $params->{username},
          realm        => $params->{realm},
          new_password => $password;
    }
};

get '/update_current_user' => sub {
    update_current_user name => "I love cider";
};

get '/update_user_name/:realm' => sub {
    my $realm = param 'realm';
    YAML::Dump update_user 'mark', realm => $realm, name => "Wiltshire Apples $realm";
};

get '/update_user_role/:realm' => sub {
    my $realm = param 'realm';
    YAML::Dump update_user 'mark', realm => $realm, role => { CiderDrinker => 1 };
};

get '/get_user_details/:user' => sub {
    content_type 'text/x-yaml';
    my $user = get_user_details param('user');
    if ( blessed($user) ) {
        if ( $user->isa('DBIx::Class::Row')) {
            $user = +{ $user->get_columns };
        }
        else {
            # assume some kind of hash-backed object
            $user = \%$user;
        }
    }
    YAML::Dump $user;
};

get '/get_user_mark/:realm' => sub {
    my $realm = param 'realm';
    content_type 'text/x-yaml';
    my $user = get_user_details 'mark', $realm;
    if ( blessed($user) ) {
        if ( $user->isa('DBIx::Class::Row')) {
            $user = +{ $user->get_columns };
        }
        else {
            # assume some kind of hash-backed object
            $user = \%$user;
        }
    }
    YAML::Dump $user;
};

get '/can_test_realm_priority' => sub {
    app->with_plugin('Auth::Extensible')->config->{realms}->{config2}
      ->{priority};
};

1;
