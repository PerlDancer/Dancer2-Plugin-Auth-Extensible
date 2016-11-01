package Dancer2::Plugin::Auth::Extensible::Test;

our $VERSION = '0.614';

=head1 NAME

Dancer2::Plugin::Auth::Extensible::Test - test suite for Auth::Extensible plugin

=cut

use warnings;
use strict;

use Carp qw(croak);
use Test::More;
use Test::Deep;
use Plack::Test;
use HTTP::Cookies;
use HTTP::Request::Common qw(GET POST);
use YAML ();

=head1 DESCRIPTION

Test suite for L<Dancer2::Plugin::Auth::Extensible> which can also be used
by external providers. If you have written your own provider then you really
want to use this since it should make sure your provider conforms as
L<Dancer2::Plugin::Auth::Extensible> expects it to. It will also save you
writing piles of tests yourself.

=head1 FUNCTIONS

=head2 testme $psgi_app

=cut

my $jar = HTTP::Cookies->new();

my %dispatch = (
    auth_provider                   => \&auth_provider,
    authenticate_user               => \&authenticate_user,
    create_user                     => \&create_user,
    get_user_details                => \&get_user_details,
    logged_in_user                  => \&logged_in_user,
    logged_in_user_lastlogin        => \&logged_in_user_lastlogin,
    logged_in_user_password_expired => \&logged_in_user_password_expired,
    password_reset_send             => \&password_reset_send,
    realm_count                     => \&realm_count,
    realm_names                     => \&realm_names,
    require_all_roles               => \&require_all_roles,
    require_any_role                => \&require_any_role,
    require_login                   => \&require_login,
    require_role                    => \&require_role,
    update_current_user             => \&update_current_user,
    update_user                     => \&update_user,
    user_has_role                   => \&user_has_role,
    user_password                   => \&user_password,
    user_roles                      => \&user_roles,
    welcome_send                    => \&welcome_send,
);

# Provider methods needed by plugin tests.
# These are assumed to be correct. If they are not then some provider tests
# should fail and we can fixup later.
my %dependencies = (
    authenticate_user => ['authenticate_user'],
    create_user => [ 'get_user_details', 'create_user', 'set_user_details', ],
    get_user_details => ['get_user_details'],
    logged_in_user   => ['get_user_details'],
    logged_in_user_password_expired =>
      [ 'get_user_details', 'password_expired' ],
    password_reset_send => ['set_user_details'],
    require_all_roles   => [ 'get_user_details', 'get_user_roles' ],
    require_any_role    => [ 'get_user_details', 'get_user_roles' ],
    require_login       => ['get_user_details'],
    require_role        => [ 'get_user_details', 'get_user_roles' ],
    update_current_user => ['set_user_details'],
    update_user         => ['set_user_details'],
    user_has_role       => ['get_user_roles'],
    user_password =>
      [ 'get_user_by_code', 'authenticate_user', 'set_user_details' ],
    user_roles => ['get_user_roles'],
);

my ( $test, $trap );

sub testme {
    BAIL_OUT "Please upgrade your provider to the latest version. Dancer2::Plugin::Auth::Extensible no longer supports the old \"testme\" tests.";
}

sub runtests {
    my $app = shift;

    $test = Plack::Test->create($app);
    $trap = TestApp->dancer_app->logger_engine->trapper;

    my $res = get('/provider_can');
    BAIL_OUT "Unable to determine what methods the provider supports"
      unless $res->is_success;

    my $ret = YAML::Load $res->content;

    BAIL_OUT "Unexpected response to /provider_can"
      unless ref($ret) eq 'ARRAY';

    my @provider_can = @$ret;

    # main plugin tests
  TEST: foreach my $test ( keys %dispatch ) {
        foreach my $dep ( @{ $dependencies{$test} || [] } ) {
            if ( !grep { $_ eq $dep } @provider_can ) {
                diag "Provider has no method $dep so skipping $test tests.";
                next TEST;
            }
        }
        note "Testing plugin $test";
        # TODO: remove this eval once all tests are written
        eval { $dispatch{$test}->(); 1; } or do {
            my $err = $@ || "Bogus error";
            #diag "TEST MISSING: $test"
            #if $err =~ /Undefined subroutine.+$test/;
        };
    }
}

sub get {
    my $uri = shift;
    my $req = GET "http://localhost$uri";
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    $jar->extract_cookies($res);
    return $res;
}

sub post {
    my $uri    = shift;
    my $params = shift || [];
    my $req    = POST "http://localhost$uri", $params;
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    $jar->extract_cookies($res);
    return $res;
}

# provider_get_user_roles

sub provider_get_user_roles {
    my $res;

    # undef username

    $res = post('/provider_get_user_roles', [realm => 'config1']);
    ok $res->is_success,"get_user_roles with undef username lives";
    is $res->content, '(undef)', '... and return is undef.';

    # empty username

    $res = post( '/provider_get_user_roles',
        [ realm => 'config1', username => '' ] );
    ok $res->is_success, "get_user_roles with empty username lives";
    is $res->content, '(undef)', '... and return is undef.';

    # non-existant username

    $res = post( '/provider_get_user_roles',
        [ realm => 'config1', username => 'nosuchuser' ] );
    ok $res->is_success, "get_user_roles with non-existant username lives";
    is $res->content, '(undef)', '... and return is undef.';

    # good user

    $res = post( '/provider_get_user_roles',
        [ realm => 'config1', username => 'dave' ] );
    ok $res->is_success, "get_user_roles with real username lives";
    my $ret = YAML::Load $res->content;
    cmp_deeply $ret, [ 'BeerDrinker', 'Motorcyclist' ],
      "... and we get expected user roles returned.";

};

# provider_create_user

sub provider_create_user {
    my $res;

    # empty username

    $res = post( '/provider_create_user',
        [ realm => 'config1', username => '' ] );
    ok !$res->is_success, "create_user with empty username dies";
    is $res->code, 500, "... with a 500 code as expected.";

    # existing username

    $res = post( '/provider_create_user',
        [ realm => 'config1', username => 'dave' ] );
    ok !$res->is_success, "create_user with existing username dave dies";
    is $res->code, 500, "... with a 500 code as expected.";

    # create user

    $res = post(
        '/provider_create_user',
        [
            realm    => 'config1',
            username => 'provider_create_user',
            name     => 'Provider Create User',
        ]
    );
    ok $res->is_success, "create_user with new username lives";
    is $res->content, 'Provider Create User',
      "... and returned content shows user was created."
}

# provider_set_user_details

sub provider_set_user_details {
    my $res;

    # undef username

    $res = post('/provider_set_user_details', [realm => 'config1']);
    is $res->code, 500, "set_user_details with undef username gives 500 error.";

    # empty username

    $res = post( '/provider_set_user_details',
        [ realm => 'config1', username => '' ] );
    is $res->code, 500, "set_user_details with empty username gives 500 error.";

    # non-existant username

    $res = post( '/provider_set_user_details',
        [ realm => 'config1', username => 'nosuchuser' ] );
    ok $res->is_success, "set_user_details with non-existant username lives";
    is $res->content, '(undef)', '... and return is undef.';

}

# base

sub _test_base {
    note "test base";

    # First, without being logged in, check we can access the index page,
    # but not stuff we need to be logged in for:

    {
        my $res = get('/');
        ok $res->is_success, "Index always accessible - GET / success";
        is $res->content,    'Index always accessible',
          "...and we got expected content.";

    }

    {
        $trap->read;    # clear logs

        my $res = get('/loggedin');

        is( $res->code, 302, '[GET /loggedin] Correct code' )
          or diag explain $trap->read;

        is(
            $res->headers->header('Location'),
            'http://localhost/login?return_url=%2Floggedin',
            '/loggedin redirected to login page when not logged in'
        );
    }

    {
        $trap->read;    # clear logs

        my $res = get('/beer');

        is( $res->code, 302, '[GET /beer] Correct code' )
          or diag explain $trap->read;

        is(
            $res->headers->header('Location'),
            'http://localhost/login?return_url=%2Fbeer',
            '/beer redirected to login page when not logged in'
        );
    }

    SKIP: {
        skip "not testing roles", 2 if $ENV{D2PAE_TEST_NO_ROLES};
        $trap->read;    # clear logs

        my $res = get('/regex/a');

        is( $res->code, 302, '[GET /regex/a] Correct code' )
          or diag explain $trap->read;

        is(
            $res->headers->header('Location'),
            'http://localhost/login?return_url=%2Fregex%2Fa',
            '/regex/a redirected to login page when not logged in'
        );
    }

    # OK, now check we can't log in with fake details

    {
        $trap->read;    # clear logs

        my $res = post( '/login', [ username => 'foo', password => 'bar' ] );

        is( $res->code, 401, 'Login with fake details fails' )
          or diag explain $trap->read;
    }

  SKIP: {
        skip "Priorities not defined for this provider test", 1
          if !get('/can_test_realm_priority')->content;

        # test realm priority
        my $logs = $trap->read;
        cmp_deeply(
            $logs,
            superbagof(
                {
                    formatted => ignore(),
                    level     => 'debug',
                    message   => re(qr/realm config2/)
                },
                {
                    formatted => ignore(),
                    level     => 'debug',
                    message   => re(qr/realm config3/)
                },
                {
                    formatted => ignore(),
                    level     => 'debug',
                    message   => re(qr/realm config1/)
                },
            ),
            "Realms checked in the correct order"
        ) or diag explain $logs;
    }

    # ... and that we can log in with real details

    {
        $trap->read;    # clear logs

        my $res = post( '/login', [ username => 'dave', password => 'beer' ] );

        is( $res->code, 302, 'Login with real details succeeds' )
          or diag explain $trap->read;

        my $logs = $trap->read;
        cmp_deeply $logs,
          superbagof(
            {
                formatted => ignore(),
                level     => 'debug',
                message   => 'config1 accepted user dave'
            }
          ),
          "... and we see expected message in logs.";

        is get('/loggedin')->content, "You are logged in",
          "... and checking /loggedin route shows we are logged in";
    }

    # Now we're logged in, check we can access stuff we should...

    {
        my $res = get('/loggedin');

        is( $res->code, 200, 'Can access /loggedin now we are logged in' )
          or diag explain $trap->read;

        is(
            $res->content,
            'You are logged in',
            'Correct page content while logged in, too'
        );
    }

  SKIP: {
        skip "not testing roles", 11 if $ENV{D2PAE_TEST_NO_ROLES};
        {
            $trap->read;    # clear logs

            my $res = get('/name');

            is( $res->code, 200, 'get /name is 200' )
              or diag explain $trap->read;

            is(
                $res->content,
                'Hello, David Precious',
                'Logged in user details via logged_in_user work'
            );

        }

        {
            $trap->read;    # clear logs

            my $res = get('/roles');

            is( $res->code, 200, 'get /roles is 200' )
              or diag explain $trap->read;

            is( $res->content, 'BeerDrinker,Motorcyclist',
                'Correct roles for logged in user' );
        }

        {
            $trap->read;    # clear logs

            my $res = get('/roles/bob');

            is( $res->code, 200, 'get /roles/bob is 200' )
              or diag explain $trap->read;

            is( $res->content, 'CiderDrinker',
                'Correct roles for other user in current realm' );
        }

        # Check we can request something which requires a role we have....

        {
            $trap->read;    # clear logs

            my $res = get('/beer');

            is( $res->code, 200,
                'We can request a route (/beer) requiring a role we have...' )
              or diag explain $trap->read;
        }

        # Check we can request a route that requires any of a list of roles,
        # one of which we have:

        {
            $trap->read;    # clear logs

            my $res = get('/anyrole');

            is( $res->code, 200,
                "We can request a multi-role route requiring with any one role"
            ) or diag explain $trap->read;
        }

        {
            $trap->read;    # clear logs

            my $res = get('/allroles');

            is( $res->code, 200,
                "We can request a multi-role route with all roles required" )
              or diag explain $trap->read;
        }

        {
            $trap->read;    # clear logs

            my $res = get('/not_allroles');

            is( $res->code, 302, "/not_allroles response code 302" )
              or diag explain $trap->read;
            is(
                $res->headers->header('Location'),
                'http://localhost/login/denied?return_url=%2Fnot_allroles',
                '/not_allroles redirected to denied page'
            );
        }
    }

    # And also a route declared as a regex (this should be no different, but
    # melmothX was seeing issues with routes not requiring login when they
    # should...

    {
        $trap->read;    # clear logs

        my $res = get('/regex/a');

        is( $res->code, 200, "We can request a regex route when logged in" )
          or diag explain $trap->read;
    }

  SKIP: {
        skip "not testing roles", 3 if $ENV{D2PAE_TEST_NO_ROLES};
        {
            $trap->read;    # clear logs

            my $res = get('/piss/regex');

            is( $res->code, 200,
                "We can request a route requiring a regex role we have" )
              or diag explain $trap->read;
        }

        # ... but can't request something requiring a role we don't have

        {
            $trap->read;    # clear logs

            my $res = get('/piss');

            is( $res->code, 302,
                "Redirect on a route requiring a role we don't have" )
              or diag explain $trap->read;

            is(
                $res->headers->header('Location'),
                'http://localhost/login/denied?return_url=%2Fpiss',
                "We cannot request a route requiring a role we don't have"
            );
        }
    }

    # Check the realm we authenticated against is what we expect

    {
        $trap->read;    # clear logs

        my $res = get('/realm');

        is( $res->code, 200, 'Status code on /realm route.' )
          or diag explain $trap->read;

        is( $res->content, 'config1', 'Authenticated against expected realm' );
    }

    # Now, log out

    {
        $trap->read;    # clear logs

        my $res = get('/logout');

        is( $res->code, 302, 'Logging out returns 302' )
          or diag explain $trap->read;

        is( $res->headers->header('Location'),
            'http://localhost/',
            '/logout redirected to / (exit_page) after logging out' );
    }

    # Check we can't access protected pages now we logged out:

    {
        $trap->read;    # clear logs

        my $res = get('/loggedin');

        is( $res->code, 302, 'Status code on accessing /loggedin after logout' )
          or diag explain $trap->read;

        is(
            $res->headers->header('Location'),
            'http://localhost/login?return_url=%2Floggedin',
            '/loggedin redirected to login page after logging out'
        );
    }

    SKIP: {
        skip "not testing roles", 2 if $ENV{D2PAE_TEST_NO_ROLES};
        $trap->read;    # clear logs

        my $res = get('/beer');

        is( $res->code, 302, 'Status code on accessing /beer after logout' )
          or diag explain $trap->read;

        is(
            $res->headers->header('Location'),
            'http://localhost/login?return_url=%2Fbeer',
            '/beer redirected to login page after logging out'
        );
    }

    # OK, log back in, this time as a user from the second realm

    {
        $trap->read;    # clear logs

        my $res =
          post( '/login', { username => 'burt', password => 'bacharach' } );

        is( $res->code, 302, 'Login as user from second realm succeeds' )
          or diag explain $trap->read;

        my $logs = $trap->read;
        cmp_deeply $logs,
          superbagof(
            {
                formatted => ignore(),
                level     => 'debug',
                message   => 'config2 accepted user burt'
            }
          ),
          "... and we see expected message in logs.";

        is get('/loggedin')->content, "You are logged in",
          "... and checking /loggedin route shows we are logged in";
    }

    # And that now we're logged in again, we can access protected pages

    {
        $trap->read;    # clear logs

        my $res = get('/loggedin');

        is( $res->code, 200, 'Can access /loggedin now we are logged in again' )
          or diag explain $trap->read;
    }

    # And that the realm we authenticated against is what we expect

    {
        $trap->read;    # clear logs

        my $res = get('/realm');

        is( $res->code, 200, 'Status code on /realm route.' )
          or diag explain $trap->read;

        is( $res->content, 'config2', 'Authenticated against expected realm' );
    }

    SKIP: {
        skip "not testing roles", 2 if $ENV{D2PAE_TEST_NO_ROLES};
        $trap->read;    # clear logs

        my $res = get('/roles/bob/config1');

        is( $res->code, 200, 'Status code on /roles/bob/config1 route.' )
          or diag explain $trap->read;

        is( $res->content, 'CiderDrinker',
            'Correct roles for other user in current realm' );
    }

    # Now, log out again

    {
        $trap->read;    # clear logs

        my $res = post('/logout');

        is( $res->code, 302, 'Logging out returns 302' )
          or diag explain $trap->read;

        is( $res->headers->header('Location'),
            'http://localhost/',
            '/logout redirected to / (exit_page) after logging out' );
    }

    # Now check we can log in as a user whose password is stored hashed:

    {
        $trap->read;    # clear logs

        my $res = post(
            '/login',
            {
                username => 'hashedpassword',
                password => 'password'
            }
        );

        is( $res->code, 302, 'Login as user with hashed password succeeds' )
          or diag explain $trap->read;

        my $logs = $trap->read;
        cmp_deeply $logs,
          superbagof(
            {
                formatted => ignore(),
                level     => 'debug',
                message   => 'config2 accepted user hashedpassword'
            }
          ),
          "... and we see expected message in logs.";

        is get('/loggedin')->content, "You are logged in",
          "... and checking /loggedin route shows we are logged in";
    }

    # And that now we're logged in again, we can access protected pages

    {
        $trap->read;    # clear logs

        my $res = get('/loggedin');

        is( $res->code, 200, 'Can access /loggedin now we are logged in again' )
          or diag explain $trap->read;
    }

    # Check that the redirect URL can be set when logging in

    {
        $trap->read;    # clear logs

        # make sure we're logged out
        get('/logout');

        my $res = post(
            '/login',
            {
                username   => 'dave',
                password   => 'beer',
                return_url => '/foobar',
            }
        );

        is( $res->code, 302, 'Status code for login with return_url' )
          or diag explain $trap->read;

        is( $res->headers->header('Location'),
            'http://localhost/foobar',
            'Redirect after login to given return_url works' );

        my $logs = $trap->read;
        cmp_deeply $logs,
          superbagof(
            {
                formatted => ignore(),
                level     => 'debug',
                message   => 'config1 accepted user dave'
            }
          ),
          "... and we see expected message in logs." or diag explain $logs;

        is get('/loggedin')->content, "You are logged in",
          "... and checking /loggedin route shows we are logged in";
    }

    # Check that login route doesn't match any request string with '/login'.

    {
        $trap->read;    # clear logs

        my $res = get('/foo/login');

        is( $res->code, 404,
            "'/foo/login' URL not matched by login route regex." )
          or diag explain $trap->read;
    }

    # Now, log out again

    {
        $trap->read;    # clear logs

        my $res = post('/logout');
        is( $res->code, 302, 'Logging out returns 302' )
          or diag explain $trap->read;

        is( $res->headers->header('Location'),
            'http://localhost/',
            '/logout redirected to / (exit_page) after logging out' );
    }

    # require_login should receive a coderef

    {
        $trap->read;    # clear logs

        my $res  = get('/require_login_no_sub');
        my $logs = $trap->read;
        is @$logs, 1, "One message in the logs" or diag explain $logs;
        is $logs->[0]->{level}, 'warning', "We got a warning in the logs";
        is $logs->[0]->{message},
          'Invalid require_login usage, please see docs',
          "Warning message is as expected";
    }
    {
        $trap->read;    # clear logs

        my $res  = get('/require_login_not_coderef');
        my $logs = $trap->read;
        is @$logs, 1, "One message in the logs" or diag explain $logs;
        is $logs->[0]->{level}, 'warning', "We got a warning in the logs";
        is $logs->[0]->{message},
          'Invalid require_login usage, please see docs',
          "Warning message is as expected";
    }

    # login as dave

    {
        $trap->read;    # clear logs

        my $res = post( '/login', [ username => 'dave', password => 'beer' ] );
        is( $res->code, 302, 'Login with real details succeeds' )
          or diag explain $trap->read;

        my $logs = $trap->read;
        cmp_deeply $logs,
          superbagof(
            {
                formatted => ignore(),
                level     => 'debug',
                message   => 'config1 accepted user dave'
            }
          ),
          "... and we see expected message in logs.";

        is get('/loggedin')->content, "You are logged in",
          "... and checking /loggedin route shows we are logged in";
    }

    # 2 arg user_has_role
  SKIP: {
        skip "not testing roles", 6 if $ENV{D2PAE_TEST_NO_ROLES};
        {
            $trap->read;    # clear logs

            my $res = get('/does_dave_drink_beer');
            is $res->code, 200, "/does_dave_drink_beer response is 200"
              or diag explain $trap->read;
            ok $res->content, "yup - dave drinks beer";
        }
        {
            $trap->read;    # clear logs

            my $res = get('/does_dave_drink_cider');
            is $res->code, 200, "/does_dave_drink_cider response is 200"
              or diag explain $trap->read;
            ok !$res->content, "no way does dave drink cider";
        }
        {
            $trap->read;    # clear logs

            my $res = get('/does_undef_drink_beer');
            is $res->code, 200, "/does_undef_drink_beer response is 200"
              or diag explain $trap->read;
            ok !$res->content, "undefined users cannot drink";
        }
    }

    # 3 arg authenticate_user

    {
        $trap->read;    # clear logs

        my $res = get('/authenticate_user_with_realm_pass');
        is $res->code, 200,
          "/authenticate_user_with_realm_pass response is 200"
          or diag explain $trap->read;
        ok $res->content, "authentication success";
    }
    {
        $trap->read;    # clear logs

        my $res = get('/authenticate_user_with_realm_fail');
        is $res->code, 200,
          "/authenticate_user_with_realm_fail response is 200"
          or diag explain $trap->read;
        ok !$res->content, "authentication failure";
    }
    {
        $trap->read;    # clear logs

        my $res = get('/authenticate_user_with_wrong_realm');
        is $res->code, 200,
          "/authenticate_user_with_wrong_realm response is 200"
          or diag explain $trap->read;
        ok !$res->content, "authentication failure";
    }

    # user_password

    {
        $trap->read;    # clear logs

        my $res = get('/user_password?username=dave&password=beer');
        is $res->code, 200,
          "/user_password?username=dave&password=beer response is 200"
          or diag explain $trap->read;
        ok $res->content, "content shows success";
    }
    {
        $trap->read;    # clear logs

        my $res = get('/user_password?username=dave&password=cider');
        is $res->code, 200,
          "/user_password?username=dave&password=cider response is 200"
          or diag explain $trap->read;
        ok !$res->content, "content shows fail";
    }
    {
        $trap->read;    # clear logs

        my $res =
          get('/user_password?username=dave&password=beer&realm=config1');

        is $res->code, 200,
"/user_password?username=dave&password=beer&realm=config1 response is 200"
          or diag explain $trap->read;
        ok $res->content, "content shows success";
    }
    {
        $trap->read;    # clear logs

        my $res =
          get('/user_password?username=dave&password=beer&realm=config2');

        is $res->code, 200,
"/user_password?username=dave&password=beer&realm=config2 response is 200"
          or diag explain $trap->read;
        ok !$res->content, "content shows fail";
    }
    {
        $trap->read;    # clear logs

        my $res = get('/user_password?password=beer');
        is $res->code, 200, "/user_password?password=beer response is 200"
          or diag explain $trap->read;
        ok $res->content, "content shows success";
    }
    {
        $trap->read;    # clear logs

        my $res = get('/user_password?password=cider');
        is $res->code, 200, "/user_password?password=cider response is 200"
          or diag explain $trap->read;
        ok !$res->content, "content shows fail";
    }

  SKIP: {
        skip "not testing get_user_details", 6
          if $ENV{D2PAE_TEST_NO_USER_DETAILS};
        {
            my $res = get('/get_user_details/dave');
            is $res->code, 200, "/get_user_details/dave response is 200"
              or diag explain $trap->read;

            my $user = YAML::Load $res->content;
            cmp_deeply $user,
              superhashof( { name => 'David Precious' } ),
              "We have Dave's name in the response"
              or diag explain $user;
        }
        {
            my $res = get('/get_user_details/burt');
            is $res->code, 200, "/get_user_details/burt response is 200"
              or diag explain $trap->read;
        }
    }

    # cleanup
    get('/logout');
}

# create_user

sub _test_create_user {

    note "test create_user";

    #for my $realm (qw/config1 config2/) {
    for my $realm (qw/config1 config2/) {

        my $data = [
            username => 'newuser',
            password => "pish_$realm",
            realm    => $realm,
        ];

        # First create a user

        {
            $trap->read;    # clear logs

            my $res = post( "/create_user", $data );

            is $res->code, 200, "/create_user response is 200"
              or diag explain $trap->read;
        }

        # Then try logging in with that user

        {
            $trap->read;    # clear logs

            my $res = post( '/login', $data );

            is( $res->code, 302, 'Login with newly created user succeeds' )
              or diag explain $trap->read;

            my $logs = $trap->read;
            cmp_deeply $logs,
              superbagof(
                {
                    formatted => ignore(),
                    level     => 'debug',
                    message   => "$realm accepted user newuser"
                }
              ),
              "... and we see expected message in logs." or diag explain $res;

            is get('/loggedin')->content, "You are logged in",
              "... and checking /loggedin route shows we are logged in";

            get('/logout');
        }

    }

    # create user with `email_welcome` so we can test reset code

    my $data = [
        username      => 'newuserwithcode',
        realm         => 'config1',
        email_welcome => 1,
    ];

    {
        $trap->read;    # clear logs

        my $res = post( "/create_user", $data );

        is $res->code, 200, "/create_user with welcome_send=>1 response is 200"
          or diag explain $trap->read;
    }
 
    {
        # the args passed to 'welcome_send' sub
        my $args = $Dancer2::Plugin::Auth::Extensible::Test::App::data;
        like $args->{code}, qr/^\w{32}$/, "... and we have a reset code";

        my $res = get("/login/$args->{code}");
        diag explain $res;
    }

}

# update_user

sub _test_update_user {

    note "test update_user";

    for my $realm (qw/config1 config2/) {

        # First test a standard user details update.

        {
            $trap->read;    # clear logs

            # Get the current user settings, and make sure name is not what
            # we're going to change it to.
            my $res = get("/get_user_mark/$realm");
            is $res->code, 200, "get /get_user_mark/$realm is 200"
              or diag explain $trap->read;

            my $user = YAML::Load $res->content;
            my $name = $user->{name} || '';
            cmp_ok(
                $name, 'ne',
                "Wiltshire Apples $realm",
                "Name is not currently Wiltshire Apples $realm"
            );
        }
        {
            $trap->read;    # clear logs

            # Update the user
            my $res = get("/update_user_name/$realm");
            is $res->code, 200, "get /update_user_name/$realm is 200"
              or diag explain $trap->read;

            $trap->read;    # clear logs

            # check it
            $res = get("/get_user_mark/$realm");
            is $res->code, 200, "get /get_user_mark/$realm is 200"
              or diag explain $trap->read;

            my $user = YAML::Load $res->content;
            cmp_ok(
                $user->{name}, 'eq',
                "Wiltshire Apples $realm",
                "Name is now Wiltshire Apples $realm"
            );
        }
    }
}

# update_roles
# This is pretty much DBIC provider at the moment until D2PAE itself defines
# how role changes can be performed.

sub _test_update_roles {

    note "test update_user";

    for my $realm (qw/config1 config2/) {

        # Now we're going to update the current user and add a role

        {
            $trap->read;    # clear logs

            # First login as the test user
            my $res = post(
                '/login',
                [
                    username => 'mark',
                    password => "wantscider",
                    realm    => $realm
                ]
            );

            is( $res->code, 302,
                "Login with real details succeeds (realm $realm)" );

            my $logs = $trap->read;
            cmp_deeply $logs,
              superbagof(
                {
                    formatted => ignore(),
                    level     => 'debug',
                    message   => "$realm accepted user mark"
                }
              ),
              "... and we see expected message in logs.";

            is get('/loggedin')->content, "You are logged in",
              "... and checking /loggedin route shows we are logged in";

            $trap->read;    # clear logs

            # Update the "current" user, that we logged in above
            $res = get("/update_current_user");
            is $res->code, 200, "get /update_current_user is 200"
              or diag explain $trap->read;

            $trap->read;    # clear logs

            # Check the update has worked
            $res = get("/get_user_mark/$realm");
            is $res->code, 200, "get /get_user_mark/$realm is 200"
              or diag explain $trap->read;

            my $user = YAML::Load $res->content;

            cmp_ok( $user->{name}, 'eq', "I love cider",
                "Name is now I love cider" );

            $trap->read;    # clear logs

            # Now the role. First check that the role doesn't work.
            $res = get('/cider');
            is( $res->code, 302, "[GET /cider] Correct code for realm $realm" );

            diag explain $trap->read;    # clear logs

            # Now add the role
            $res = get("/update_user_role/$realm");

            diag explain $trap->read;    # clear logs

            # And see whether we're now allowed access
            $res = get('/cider');
            is( $res->code, 200,
"We can request a route (/cider) requiring a role we have (realm $realm)"
            );

            $trap->read;                 # clear logs

            $res = post('/logout');
        }
    }
}

# password_reset

sub _test_password_reset {
    croak "FIXME: no password_reset tests";
}

# user_password

sub _test_user_password {
    croak "FIXME: no user_password tests";
}

# lastlogin

sub _test_lastlogin {
    croak "FIXME: no lastlogin tests";
}

# expired

sub _test_expired {
    croak "FIXME: no expired tests";
}

# reset code

sub _test_reset_code {

    note "test reset_code";

    {
        $trap->read;    # clear logs
        my $res = get('/user_password?code=');
        is $res->code, 200, "/user_password?code= response is 200"
          or diag explain $trap->read;
        ok !$res->content, "content shows fail";
        my $logs = $trap->read;
        ok !@$logs, "No log message";
    }
    {
        $trap->read;    # clear logs
        my $res = get('/user_password?code=beer');
        is $res->code, 200, "/user_password?code=beer response is 200"
          or diag explain $trap->read;
        ok !$res->content, "content shows fail";
        my $logs = $trap->read;
        is $logs->[0]->{level}, 'debug', "we got a debug log message";
        like $logs->[0]->{message},
          qr/^No user found in realm config\d with code beer$/,
          "message is: No user found in realm configX with code beer";
    }
    {
        $trap->read;    # clear logs
        my $res = get('/user_password?new_password=beer');
        is $res->code, 500, "/user_password?new_password=beer response is 500"
          or diag explain $trap->read;
        my $logs = $trap->read;
        is $logs->[0]->{level}, 'error', "we got a debug log message";
        like $logs->[0]->{message},
          qr/^Route exception: No username specified and no logged-in user/,
"message is: 'Route exception: No username specified and no logged-in user'";
    }
    {
        $trap->read;    # clear logs
        my $res = get('/user_password?new_password=beer&realm=config1');
        is $res->code, 500,
          "/user_password?new_password=beer&realm=config1 response is 500"
          or diag explain $trap->read;
        my $logs = $trap->read;
        is $logs->[0]->{level}, 'error', "we got a debug log message";
        like $logs->[0]->{message},
          qr/^Route exception: set_user_password was not implemented/,
"message is: 'Route exception: set_user_password was not implemented...'";
    }
}

1;
