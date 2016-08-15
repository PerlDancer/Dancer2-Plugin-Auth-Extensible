package Dancer2::Plugin::Auth::Extensible::Test;

our $VERSION = '0.610';

=head1 NAME

Dancer2::Plugin::Auth::Extensible::Test - test suite for Auth::Extensible plugin

=cut

use warnings;
use strict;

use Carp;
use Test::More;
use Test::Deep;
use Plack::Test;
use HTTP::Request::Common qw(GET HEAD PUT POST DELETE);
use YAML ();

=head1 DESCRIPTION

Test suite for L<Dancer2::Plugin::Auth::Extensible> which can also be used
by external providers. If you have written your own provider then you really
want to use this since it should make sure your provider conforms as
L<Dancer2::Plugin::Auth::Extensible> expects it to. It will also save you
writing piles of tests yourself.

=head1 FUNCTIONS

=head2 testme $psgi_app @test_names?

Current valid test names:

=over

=item * base

This test is always run whether or not it is supplied in C<@test_names>. This
tests all methods/functions that all providers must provide.

=item * create_user

Test provider's C<create_user> method.

=item * update_user

Test provider's C<update_user> and C<update_current_user> methods.

=item * password_reset

=item * user_password

=item * lastlogin

Test provider's C<password_expired> function.

=item * expired

=back

=cut

sub testme {
    my $app = shift;
    my %args = map { $_ => 1} @_;

    # always run base tests
    delete $args{base};
    test_psgi $app, _test_base();

    foreach my $name (
        qw/ create_user update_user update_roles password_reset user_password
        lastlogin expired reset_code/
      )
    {
        if ( delete $args{$name} ) {
            test_psgi $app, eval "_test_$name()";
        }
        else {
            test_psgi $app, eval "_test_no_$name()";
        }
    }

    my @remaining = keys %args;

    ok !@remaining, "No test names left" or diag explain @remaining;
}

# base

sub _test_base {

    note "test base";

    my $sub = sub {

        my $trap = TestApp->dancer_app->logger_engine->trapper;

        my $cb = shift;

        # First, without being logged in, check we can access the index page,
        # but not stuff we need to be logged in for:

        is (
            $cb->( GET '/' )->content,
            'Index always accessible',
            'Index accessible while not logged in'
        ) or diag explain $trap->read;

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/loggedin' );

            is( $res->code, 302, '[GET /loggedin] Correct code' )
                or diag explain $trap->read;

            is(
                $res->headers->header('Location'),
                'http://localhost/login?return_url=%2Floggedin',
                '/loggedin redirected to login page when not logged in'
            );
        }

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/beer' );

            is( $res->code, 302, '[GET /beer] Correct code' )
                or diag explain $trap->read;

            is(
                $res->headers->header('Location'),
                'http://localhost/login?return_url=%2Fbeer',
                '/beer redirected to login page when not logged in'
            );
        }

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/regex/a' );

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
            $trap->read; # clear logs

            my $res =
              $cb->( POST '/login', [ username => 'foo', password => 'bar' ] );

            is( $res->code, 401, 'Login with fake details fails' )
              or diag explain $trap->read;
        }

        my @headers;

        # ... and that we can log in with real details

        {
            $trap->read; # clear logs

            my $res = $cb->( POST '/login',
                [ username => 'dave', password => 'beer' ] );

            is( $res->code, 302, 'Login with real details succeeds')
                or diag explain $trap->read;

            # Get cookie with session id
            my $cookie = $res->header('Set-Cookie');
            $cookie =~ s/^(.*?);.*$/$1/s;
            ok ($cookie, "Got the cookie: $cookie");
            @headers = (Cookie => $cookie);
        }

        # Now we're logged in, check we can access stuff we should...

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/loggedin' , @headers);

            is ($res->code, 200, 'Can access /loggedin now we are logged in')
                or diag explain $trap->read;

            is ($res->content, 'You are logged in',
                'Correct page content while logged in, too');
        }

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/name', @headers);

            is ($res->code, 200, 'get /name is 200')
                or diag explain $trap->read;

            is ($res->content, 'Hello, David Precious',
                'Logged in user details via logged_in_user work');

        }

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/roles', @headers );

            is ($res->code, 200, 'get /roles is 200')
                or diag explain $trap->read;

            is( $res->content, 'BeerDrinker,Motorcyclist',
                'Correct roles for logged in user' );
        }

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/roles/bob', @headers );

            is ($res->code, 200, 'get /roles/bob is 200')
                or diag explain $trap->read;

            is( $res->content, 'CiderDrinker',
                'Correct roles for other user in current realm' );
        }

        # Check we can request something which requires a role we have....

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/beer', @headers );

            is( $res->code, 200,
                'We can request a route (/beer) requiring a role we have...' )
                or diag explain $trap->read;
        }

        # Check we can request a route that requires any of a list of roles,
        # one of which we have:

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/anyrole', @headers );

            is ($res->code, 200,
                "We can request a multi-role route requiring with any one role")
                or diag explain $trap->read;
        }

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/allroles', @headers );

            is ($res->code, 200,
                "We can request a multi-role route with all roles required")
                or diag explain $trap->read;
        }

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/not_allroles', @headers );

            is ($res->code, 302, "/not_allroles response code 302")
                or diag explain $trap->read;
            is(
                $res->headers->header('Location'),
                'http://localhost/login/denied?return_url=%2Fnot_allroles',
                '/not_allroles redirected to denied page'
            );
        }

        # And also a route declared as a regex (this should be no different, but
        # melmothX was seeing issues with routes not requiring login when they
        # should...

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/regex/a', @headers );

            is ($res->code, 200, "We can request a regex route when logged in")
                or diag explain $trap->read;
        }

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/piss/regex', @headers );

            is( $res->code, 200,
                "We can request a route requiring a regex role we have" )
                or diag explain $trap->read;
        }

        # ... but can't request something requiring a role we don't have

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/piss', @headers );

            is ($res->code, 302,
                "Redirect on a route requiring a role we don't have")
                or diag explain $trap->read;

            is ($res->headers->header('Location'),
                'http://localhost/login/denied?return_url=%2Fpiss',
                "We cannot request a route requiring a role we don't have");
        }

        # Check the realm we authenticated against is what we expect

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/realm', @headers );

            is($res->code, 200, 'Status code on /realm route.')
                or diag explain $trap->read;

            is( $res->content, 'config1',
                'Authenticated against expected realm' );
        }

        # Now, log out

        {
            $trap->read; # clear logs

            my $res = $cb->(POST '/logout', @headers );

            is($res->code, 302, 'Logging out returns 302')
                or diag explain $trap->read;

            is($res->headers->header('Location'),
               'http://localhost/',
               '/logout redirected to / (exit_page) after logging out');
        }

        # Check we can't access protected pages now we logged out:

        {
            $trap->read; # clear logs

            my $res = $cb->(GET '/loggedin', @headers);

            is( $res->code, 302,
                'Status code on accessing /loggedin after logout' )
                or diag explain $trap->read;

            is($res->headers->header('Location'),
               'http://localhost/login?return_url=%2Floggedin',
               '/loggedin redirected to login page after logging out');
        }

        {
            $trap->read; # clear logs

            my $res = $cb->(GET '/beer', @headers);

            is($res->code, 302, 'Status code on accessing /beer after logout')
                or diag explain $trap->read;

            is($res->headers->header('Location'),
               'http://localhost/login?return_url=%2Fbeer',
               '/beer redirected to login page after logging out');
        }

        # OK, log back in, this time as a user from the second realm

        {
            $trap->read; # clear logs

            my $res = $cb->(
                POST '/login',
                { username => 'burt', password => 'bacharach' }
            );

            is($res->code, 302, 'Login as user from second realm succeeds')
                or diag explain $trap->read;

            # Get cookie with session id
            my $cookie = $res->header('Set-Cookie');
            $cookie =~ s/^(.*?);.*$/$1/s;
            ok ($cookie, "Got the cookie: $cookie");
            @headers = (Cookie => $cookie);
        }


        # And that now we're logged in again, we can access protected pages

        {
            $trap->read; # clear logs

            my $res = $cb->(GET '/loggedin', @headers);

            is( $res->code, 200,
                'Can access /loggedin now we are logged in again' )
                or diag explain $trap->read;
        }

        # And that the realm we authenticated against is what we expect

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/realm', @headers );

            is($res->code, 200, 'Status code on /realm route.')
                or diag explain $trap->read;

            is($res->content, 'config2', 'Authenticated against expected realm');
        }

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/roles/bob/config1', @headers );

            is($res->code, 200, 'Status code on /roles/bob/config1 route.')
                or diag explain $trap->read;

            is( $res->content, 'CiderDrinker',
                'Correct roles for other user in current realm' );
        }

        # Now, log out again

        {
            $trap->read; # clear logs

            my $res = $cb->(POST '/logout', @headers );

            is($res->code, 302, 'Logging out returns 302')
                or diag explain $trap->read;

            is($res->headers->header('Location'),
               'http://localhost/',
               '/logout redirected to / (exit_page) after logging out');
        }

        # Now check we can log in as a user whose password is stored hashed:

        {
            $trap->read; # clear logs

            my $res = $cb->(
                POST '/login',
                {
                    username => 'hashedpassword',
                    password => 'password'
                }
            );

            is($res->code, 302, 'Login as user with hashed password succeeds')
                or diag explain $trap->read;

            # Get cookie with session id
            my $cookie = $res->header('Set-Cookie');
            $cookie =~ s/^(.*?);.*$/$1/s;
            ok ($cookie, "Got the cookie: $cookie");
            @headers = (Cookie => $cookie);
        }

        # And that now we're logged in again, we can access protected pages

        {
            $trap->read; # clear logs

            my $res = $cb->(GET '/loggedin', @headers);

            is( $res->code, 200,
                'Can access /loggedin now we are logged in again' )
                or diag explain $trap->read;
        }

        # Check that the redirect URL can be set when logging in

        {
            $trap->read; # clear logs

            my $res = $cb->(POST '/login', {
                username => 'dave',
                password => 'beer',
                return_url => '/foobar',
            });

            is($res->code, 302, 'Status code for login with return_url')
                or diag explain $trap->read;

            is($res->headers->header('Location'),
               'http://localhost/foobar',
               'Redirect after login to given return_url works');
        }
        
        # Check that login route doesn't match any request string with '/login'.

        {
            $trap->read; # clear logs

            my $res = $cb->(GET '/foo/login', @headers);

            is( $res->code, 404,
                "'/foo/login' URL not matched by login route regex." )
                or diag explain $trap->read;
        }

        # Now, log out again

        {
            $trap->read; # clear logs

            my $res = $cb->(POST '/logout', @headers );
            is($res->code, 302, 'Logging out returns 302')
                or diag explain $trap->read;

            is($res->headers->header('Location'),
               'http://localhost/',
               '/logout redirected to / (exit_page) after logging out');
        }

        # require_login should receive a coderef

        {
            $trap->read; # clear logs

            my $res  = $cb->( GET '/require_login_no_sub' );
            my $logs = $trap->read;
            is @$logs, 1, "One message in the logs" or diag explain $logs;
            is $logs->[0]->{level}, 'warning', "We got a warning in the logs";
            is $logs->[0]->{message},
              'Invalid require_login usage, please see docs',
              "Warning message is as expected";
        }
        {
            $trap->read; # clear logs

            my $res  = $cb->( GET '/require_login_not_coderef' );
            my $logs = $trap->read;
            is @$logs, 1, "One message in the logs" or diag explain $logs;
            is $logs->[0]->{level}, 'warning', "We got a warning in the logs";
            is $logs->[0]->{message},
              'Invalid require_login usage, please see docs',
              "Warning message is as expected";
        }

        # login as dave

        {
            $trap->read; # clear logs

            my $res = $cb->( POST '/login',
                [ username => 'dave', password => 'beer' ] );
            is( $res->code, 302, 'Login with real details succeeds' )
                or diag explain $trap->read;

            # Get cookie with session id
            my $cookie = $res->header('Set-Cookie');
            $cookie =~ s/^(.*?);.*$/$1/s;
            ok( $cookie, "Got the cookie: $cookie" );
            @headers = ( Cookie => $cookie );
        }

        # 2 arg user_has_role

        {
            $trap->read; # clear logs

            my $res = $cb->(GET '/does_dave_drink_beer', @headers);
            is $res->code, 200, "/does_dave_drink_beer response is 200"
                or diag explain $trap->read;
            ok $res->content, "yup - dave drinks beer";
        }
        {
            $trap->read; # clear logs

            my $res = $cb->(GET '/does_dave_drink_cider', @headers);
            is $res->code, 200, "/does_dave_drink_cider response is 200"
                or diag explain $trap->read;
            ok !$res->content, "no way does dave drink cider";
        }
        {
            $trap->read; # clear logs

            my $res = $cb->(GET '/does_undef_drink_beer', @headers);
            is $res->code, 200, "/does_undef_drink_beer response is 200"
                or diag explain $trap->read;
            ok !$res->content, "undefined users cannot drink";
        }

        # 3 arg authenticate_user

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/authenticate_user_with_realm_pass' );
            is $res->code, 200,
              "/authenticate_user_with_realm_pass response is 200"
                  or diag explain $trap->read;
            ok $res->content, "authentication success";
        }
        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/authenticate_user_with_realm_fail' );
            is $res->code, 200,
              "/authenticate_user_with_realm_fail response is 200"
                  or diag explain $trap->read;
            ok !$res->content, "authentication failure";
        }
        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/authenticate_user_with_wrong_realm' );
            is $res->code, 200,
              "/authenticate_user_with_wrong_realm response is 200"
                  or diag explain $trap->read;
            ok !$res->content, "authentication failure";
        }

        # user_password

        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/user_password?username=dave&password=beer' );
            is $res->code, 200,
              "/user_password?username=dave&password=beer response is 200"
                  or diag explain $trap->read;
            ok $res->content, "content shows success";
        }
        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/user_password?username=dave&password=cider' );
            is $res->code, 200,
              "/user_password?username=dave&password=cider response is 200"
                  or diag explain $trap->read;
            ok !$res->content, "content shows fail";
        }
        {
            $trap->read; # clear logs

            my $res = $cb->( GET
                  '/user_password?username=dave&password=beer&realm=config1' );
            is $res->code, 200,
              "/user_password?username=dave&password=beer&realm=config1 response is 200"
                  or diag explain $trap->read;
            ok $res->content, "content shows success";
        }
        {
            $trap->read; # clear logs

            my $res = $cb->( GET
                  '/user_password?username=dave&password=beer&realm=config2' );
            is $res->code, 200,
              "/user_password?username=dave&password=beer&realm=config2 response is 200"
                  or diag explain $trap->read;
            ok !$res->content, "content shows fail";
        }
        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/user_password?password=beer', @headers );
            is $res->code, 200,
              "/user_password?password=beer response is 200"
                  or diag explain $trap->read;
            ok $res->content, "content shows success";
        }
        {
            $trap->read; # clear logs

            my $res = $cb->( GET '/user_password?password=cider', @headers );
            is $res->code, 200,
              "/user_password?password=cider response is 200"
                  or diag explain $trap->read;
            ok !$res->content, "content shows fail";
        }
    };
};

# create_user

sub _test_create_user {
    
    note "test create_user";

    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;

        for my $realm (qw/config1 config2/) {

            # First create a user

            {
                $trap->read; # clear logs

                my $res = $cb->( GET "/create_user/$realm" );

                is $res->code, 200,
                  "/create_user response is 200"
                      or diag explain $trap->read;
            }

            # Then try logging in with that user

            {
                $trap->read; # clear logs

                my $res = $cb->(
                    POST '/login',
                    [
                        username => 'newuser',
                        password => "pish_$realm",
                        realm    => $realm
                    ]
                );
                is( $res->code, 302, 'Login with newly created user succeeds' )
                    or diag explain $trap->read;
            }

        }

    }
};

sub _test_no_create_user {
    note "NOTE: not testing create_user";
    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;
    }
};

# update_user

sub _test_update_user {

    note "test update_user";

    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;

        for my $realm (qw/config1 config2/) {

            # First test a standard user details update.

            {
                $trap->read; # clear logs

                # Get the current user settings, and make sure name is not what
                # we're going to change it to.
                my $res = $cb->( GET "/get_user_mark/$realm" );
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
                $trap->read; # clear logs

                # Update the user
                my $res = $cb->( GET "/update_user_name/$realm" );
                is $res->code, 200, "get /update_user_name/$realm is 200" 
                    or diag explain $trap->read;

                $trap->read; # clear logs

                # check it
                $res = $cb->( GET "/get_user_mark/$realm" );
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
};

sub _test_no_update_user {
    note "NOTE: not testing update_user";
    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;
    }
};


# update_roles
# This is pretty much DBIC provider at the moment until D2PAE itself defines
# how role changes can be performed.

sub _test_update_roles {

    note "test update_user";

    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;

        for my $realm (qw/config1 config2/) {

            # Now we're going to update the current user and add a role

            {
                $trap->read; # clear logs

                # First login as the test user
                my $res = $cb->(
                    POST '/login',
                    [
                        username => 'mark',
                        password => "wantscider",
                        realm    => $realm
                    ]
                );

                is( $res->code, 302,
                    "Login with real details succeeds (realm $realm)" );

                # Get cookie with session id
                my $cookie = $res->header('Set-Cookie');
                $cookie =~ s/^(.*?);.*$/$1/s;
                ok ($cookie, "Got the cookie: $cookie");
                my @headers = (Cookie => $cookie);

                $trap->read; # clear logs

                # Update the "current" user, that we logged in above
                $res = $cb->( GET "/update_current_user", @headers );
                is $res->code, 200, "get /update_current_user is 200"
                    or diag explain $trap->read;

                $trap->read; # clear logs

                # Check the update has worked
                $res = $cb->( GET "/get_user_mark/$realm" );
                is $res->code, 200, "get /get_user_mark/$realm is 200"
                    or diag explain $trap->read;

                my $user = YAML::Load $res->content;

                cmp_ok( $user->{name}, 'eq', "I love cider",
                    "Name is now I love cider" );

                $trap->read; # clear logs

                # Now the role. First check that the role doesn't work.
                $res = $cb->( GET '/cider', @headers );
                is( $res->code, 302,
                    "[GET /cider] Correct code for realm $realm" );

                diag explain $trap->read; # clear logs

                # Now add the role
                $res = $cb->( GET "/update_user_role/$realm" );

                diag explain $trap->read; # clear logs

                # And see whether we're now allowed access
                $res = $cb->( GET '/cider', @headers );
                is( $res->code, 200, "We can request a route (/cider) requiring a role we have (realm $realm)");

                $trap->read; # clear logs

                $res = $cb->(POST '/logout', @headers);
            }
        }
    }
};

sub _test_no_update_roles {
    note "NOTE: not testing update_roles";
    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;
    }
};

# password_reset

sub _test_password_reset {
    croak "FIXME: no password_reset tests";
    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;
    }
};

sub _test_no_password_reset {
    note "NOTE: not testing password_reset";
    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;
    }
};

# user_password

sub _test_user_password {
    croak "FIXME: no user_password tests";
    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;
    }
};

sub _test_no_user_password {
    note "NOTE: not testing user_password";
    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;
    }
};

# lastlogin

sub _test_lastlogin {
    croak "FIXME: no lastlogin tests";
    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;
    }
};

sub _test_no_lastlogin {
    note "NOTE: not testing lastlogin";
    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;
    }
};

# expired

sub _test_expired {
    croak "FIXME: no expired tests";
    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;
    }
};

sub _test_no_expired {
    note "NOTE: not testing expired";
    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;
    }
};

# reset code

sub _test_reset_code {

    note "test reset_code";

    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;

        my @headers;
        {
            $trap->read; # clear logs
            my $res = $cb->( GET '/user_password?code=', @headers );
            is $res->code, 200,
              "/user_password?code= response is 200"
              or diag explain $trap->read;
            ok !$res->content, "content shows fail";
            my $logs = $trap->read;
            ok !@$logs, "No log message";
        }
        {
            $trap->read; # clear logs
            my $res = $cb->( GET '/user_password?code=beer', @headers );
            is $res->code, 200,
              "/user_password?code=beer response is 200"
              or diag explain $trap->read;
            ok !$res->content, "content shows fail";
            my $logs = $trap->read;
            is $logs->[0]->{level}, 'debug', "we got a debug log message";
            like $logs->[0]->{message},
              qr/^No user found in realm config\d with code beer$/,
              "message is: No user found in realm configX with code beer";
        }
        {
            $trap->read; # clear logs
            my $res = $cb->( GET '/user_password?new_password=beer', @headers );
            is $res->code, 500,
              "/user_password?new_password=beer response is 500"
              or diag explain $trap->read;
            my $logs = $trap->read;
            is $logs->[0]->{level}, 'error', "we got a debug log message";
            like $logs->[0]->{message},
              qr/^Route exception: No username specified and no logged-in user/,
              "message is: 'Route exception: No username specified and no logged-in user'";
        }
        {
            $trap->read; # clear logs
            my $res = $cb->( GET '/user_password?new_password=beer&realm=config1', @headers );
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
};

sub _test_no_reset_code {
    note "NOTE: not testing reset_code";
    my $sub = sub {
        my $trap = TestApp->dancer_app->logger_engine->trapper;
        my $cb = shift;
    }
};

1;
