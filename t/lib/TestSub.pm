package t::lib::TestSub;

use Test::More;
use Test::Deep;
use HTTP::Request::Common qw(GET HEAD PUT POST DELETE);

sub test_the_app_sub {
    my $sub = sub {

        my $trap = t::lib::TestApp->dancer_app->logger_engine->trapper;

        my $cb = shift;

        # First, without being logged in, check we can access the index page, but not
        # stuff we need to be logged in for:

        is (
            $cb->( GET '/' )->content,
            'Index always accessible',
            'Index accessible while not logged in'
        );

        {
            my $res = $cb->( GET '/loggedin' );

            is( $res->code, 302, '[GET /loggedin] Correct code' );

            is(
                $res->headers->header('Location'),
                'http://localhost/login?return_url=%2Floggedin',
                '/loggedin redirected to login page when not logged in'
            );
        }

        {
            my $res = $cb->( GET '/beer' );

            is( $res->code, 302, '[GET /beer] Correct code' );

            is(
                $res->headers->header('Location'),
                'http://localhost/login?return_url=%2Fbeer',
                '/beer redirected to login page when not logged in'
            );
        }

        {
            my $res = $cb->( GET '/regex/a' );

            is( $res->code, 302, '[GET /regex/a] Correct code' );

            is(
                $res->headers->header('Location'),
                'http://localhost/login?return_url=%2Fregex%2Fa',
                '/regex/a redirected to login page when not logged in'
            );
        }

        # OK, now check we can't log in with fake details

        {
            my $res = $cb->( POST '/login', [ username => 'foo', password => 'bar' ] );

            is( $res->code, 401, 'Login with fake details fails');
        }

        my @headers;

        # ... and that we can log in with real details

        {
            my $res = $cb->( POST '/login', [ username => 'dave', password => 'beer' ] );

            is( $res->code, 302, 'Login with real details succeeds');

            # Get cookie with session id
            my $cookie = $res->header('Set-Cookie');
            $cookie =~ s/^(.*?);.*$/$1/s;
            ok ($cookie, "Got the cookie: $cookie");
            @headers = (Cookie => $cookie);
        }

        # Now we're logged in, check we can access stuff we should...

        {
            my $res = $cb->( GET '/loggedin' , @headers);

            is ($res->code, 200, 'Can access /loggedin now we are logged in');

            is ($res->content, 'You are logged in',
                'Correct page content while logged in, too');
        }

        {
            my $res = $cb->( GET '/name', @headers);

            is ($res->content, 'Hello, David Precious',
                'Logged in user details via logged_in_user work');

        }

        {
            my $res = $cb->( GET '/roles', @headers );

            is ($res->content, 'BeerDrinker,Motorcyclist', 'Correct roles for logged in user');
        }

        {
            my $res = $cb->( GET '/roles/bob', @headers );

            is ($res->content, 'CiderDrinker', 'Correct roles for other user in current realm');
        }

        # Check we can request something which requires a role we have....
        {
            my $res = $cb->( GET '/beer', @headers );

            is ($res->code, 200, 'We can request a route (/beer) requiring a role we have...');
        }

        # Check we can request a route that requires any of a list of roles, one of
        # which we have:
        {
            my $res = $cb->( GET '/anyrole', @headers );

            is ($res->code, 200,
                "We can request a multi-role route requiring with any one role");
        }

        {
            my $res = $cb->( GET '/allroles', @headers );

            is ($res->code, 200,
                "We can request a multi-role route with all roles required");
        }

        {
            my $res = $cb->( GET '/not_allroles', @headers );

            is ($res->code, 302, "/not_allroles response code 302");
            is(
                $res->headers->header('Location'),
                'http://localhost/login/denied?return_url=%2Fnot_allroles',
                '/not_allroles redirected to denied page'
            );
        }

        # And also a route declared as a regex (this should be no different, but
        # melmothX was seeing issues with routes not requiring login when they should...

        {
            my $res = $cb->( GET '/regex/a', @headers );

            is ($res->code, 200, "We can request a regex route when logged in");
        }

        {
            my $res = $cb->( GET '/piss/regex', @headers );

            is ($res->code, 200, "We can request a route requiring a regex role we have");
        }

        # ... but can't request something requiring a role we don't have

        {
            my $res = $cb->( GET '/piss', @headers );

            is ($res->code, 302,
                "Redirect on a route requiring a role we don't have");

            is ($res->headers->header('Location'),
                'http://localhost/login/denied?return_url=%2Fpiss',
                "We cannot request a route requiring a role we don't have");
        }

        # Check the realm we authenticated against is what we expect

        {
            my $res = $cb->( GET '/realm', @headers );

            is($res->code, 200, 'Status code on /realm route.');
            is($res->content, 'config1', 'Authenticated against expected realm');
        }

        # Now, log out

        {
            my $res = $cb->(POST '/logout', @headers );

            is($res->code, 200, 'Logging out returns 200');
        }

        # Check we can't access protected pages now we logged out:

        {
            my $res = $cb->(GET '/loggedin', @headers);

            is($res->code, 302, 'Status code on accessing /loggedin after logout');

            is($res->headers->header('Location'),
               'http://localhost/login?return_url=%2Floggedin',
               '/loggedin redirected to login page after logging out');
        }

        {
            my $res = $cb->(GET '/beer', @headers);

            is($res->code, 302, 'Status code on accessing /beer after logout');

            is($res->headers->header('Location'),
               'http://localhost/login?return_url=%2Fbeer',
               '/beer redirected to login page after logging out');
        }

        # OK, log back in, this time as a user from the second realm

        {
            my $res = $cb->(POST '/login', { username => 'burt', password => 'bacharach' });

            is($res->code, 302, 'Login as user from second realm succeeds');

            # Get cookie with session id
            my $cookie = $res->header('Set-Cookie');
            $cookie =~ s/^(.*?);.*$/$1/s;
            ok ($cookie, "Got the cookie: $cookie");
            @headers = (Cookie => $cookie);
        }


        # And that now we're logged in again, we can access protected pages

        {
            my $res = $cb->(GET '/loggedin', @headers);

            is($res->code, 200, 'Can access /loggedin now we are logged in again');
        }

        # And that the realm we authenticated against is what we expect
        {
            my $res = $cb->( GET '/realm', @headers );

            is($res->code, 200, 'Status code on /realm route.');
            is($res->content, 'config2', 'Authenticated against expected realm');
        }

        {
            my $res = $cb->( GET '/roles/bob/config1', @headers );

            is($res->code, 200, 'Status code on /roles/bob/config1 route.');
            is($res->content, 'CiderDrinker', 'Correct roles for other user in current realm');
        }

        # Now, log out again
        {
            my $res = $cb->(POST '/logout', @headers );

            is($res->code, 200, 'Logged out again');
        }

        # Now check we can log in as a user whose password is stored hashed:
        {
            my $res = $cb->(POST '/login',
                            {
                                username => 'hashedpassword', password => 'password' });

            is($res->code, 302, 'Login as user with hashed password succeeds');

            # Get cookie with session id
            my $cookie = $res->header('Set-Cookie');
            $cookie =~ s/^(.*?);.*$/$1/s;
            ok ($cookie, "Got the cookie: $cookie");
            @headers = (Cookie => $cookie);
        }

        # And that now we're logged in again, we can access protected pages
        {
            my $res = $cb->(GET '/loggedin', @headers);

            is($res->code, 200, 'Can access /loggedin now we are logged in again');
        }

        # Check that the redirect URL can be set when logging in
        {
            my $res = $cb->(POST '/login', {
                username => 'dave',
                password => 'beer',
                return_url => '/foobar',
            });

            is($res->code, 302, 'Status code for login with return_url');

            is($res->headers->header('Location'),
               'http://localhost/foobar',
               'Redirect after login to given return_url works');
        }
        
        # Check that login route doesn't match any request string with '/login'.
        {
            my $res = $cb->(GET '/foo/login', @headers);

            is($res->code, 404, "'/foo/login' URL not matched by login route regex.");
        }

        # Now, log out again
        {
            my $res = $cb->(POST '/logout', @headers );
            is $res->code, 200, 'Logged out again';
        }

        # require_login should receive a coderef
        {
            $trap->read;    # clear logs
            my $res  = $cb->( GET '/require_login_no_sub' );
            my $logs = $trap->read;
            is @$logs, 1, "One message in the logs";
            is $logs->[0]->{level}, 'warning', "We got a warning in the logs";
            is $logs->[0]->{message},
              'Invalid require_login usage, please see docs',
              "Warning message is as expected";
        }
        {
            $trap->read;    # clear logs
            my $res  = $cb->( GET '/require_login_not_coderef' );
            my $logs = $trap->read;
            is @$logs, 1, "One message in the logs";
            is $logs->[0]->{level}, 'warning', "We got a warning in the logs";
            is $logs->[0]->{message},
              'Invalid require_login usage, please see docs',
              "Warning message is as expected";
        }

        # login as dave
        {
            my $res = $cb->( POST '/login',
                [ username => 'dave', password => 'beer' ] );
            is( $res->code, 302, 'Login with real details succeeds' );

            # Get cookie with session id
            my $cookie = $res->header('Set-Cookie');
            $cookie =~ s/^(.*?);.*$/$1/s;
            ok( $cookie, "Got the cookie: $cookie" );
            @headers = ( Cookie => $cookie );
        }

        # 2 arg user_has_role
        {
            my $res = $cb->(GET '/does_dave_drink_beer', @headers);
            is $res->code, 200, "/does_dave_drink_beer response is 200";
            ok $res->content, "yup - dave drinks beer";
        }
        {
            my $res = $cb->(GET '/does_dave_drink_cider', @headers);
            is $res->code, 200, "/does_dave_drink_cider response is 200";
            ok !$res->content, "no way does dave drink cider";
        }
        {
            my $res = $cb->(GET '/does_undef_drink_beer', @headers);
            is $res->code, 200, "/does_undef_drink_beer response is 200";
            ok !$res->content, "undefined users cannot drink";
        }
    }
};

1;
