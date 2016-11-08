package Dancer2::Plugin::Auth::Extensible::Test;

our $VERSION = '0.620';

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

=head2 runtests $psgi_app

This is the way to test your provider.

=head2 testme

This method no longer runs any tests but exists purely to force providers
trying to use the old tests to fail.

=cut

my $jar = HTTP::Cookies->new();

my %dispatch = (
    authenticate_user               => \&_authenticate_user,
    create_user                     => \&_create_user,
    get_user_details                => \&_get_user_details,
    login_logout                    => \&_login_logout,
    logged_in_user                  => \&_logged_in_user,
    logged_in_user_lastlogin        => \&_logged_in_user_lastlogin,
    logged_in_user_password_expired => \&_logged_in_user_password_expired,
    password_reset                  => \&_password_reset,
    password_reset_send             => \&_password_reset_send,
    require_login                   => \&_require_login,
    roles                           => \&_roles,
    update_current_user             => \&_update_current_user,
    update_user                     => \&_update_user,
    user_password                   => \&_user_password,
);

# Provider methods needed by plugin tests.
# These are assumed to be correct. If they are not then some provider tests
# should fail and we can fixup later.
my %dependencies = (
    create_user => [ 'get_user_details', 'create_user', 'set_user_details', ],
    get_user_details => ['get_user_details'],
    logged_in_user   => ['get_user_details'],
    logged_in_user_lastlogin => ['create_user'],
    logged_in_user_password_expired =>
      [ 'get_user_details', 'password_expired' ],
    password_reset      => ['get_user_by_code'],
    password_reset_send => ['set_user_details'],
    require_login       => ['get_user_details'],
    roles               => ['get_user_roles' ],
    update_current_user => ['set_user_details'],
    update_user         => ['set_user_details'],
    user_password =>
      [ 'get_user_by_code', 'authenticate_user', 'set_user_details' ],
);

my ( $test, $trap );

sub testme {
    BAIL_OUT "Please upgrade your provider to the latest version. Dancer2::Plugin::Auth::Extensible no longer supports the old \"testme\" tests.";
}

# so test can check
my @provider_can;

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

    @provider_can = @$ret;

    my @to_test = ($ENV{D2PAE_TEST_ONLY}) || keys %dispatch;

    foreach my $test ( @to_test ) {
        my @missing;
        foreach my $dep ( @{ $dependencies{$test} || [] } ) {
            push @missing, $dep if !grep { $_ eq $dep } @provider_can;
        }
      SKIP: {
            skip "Provider $test tests as provider is missing methods: "
              . join( ", ", @missing ), 1
              if @missing;

            # for safety in case one set of tests doesn't clean up carefully
            $jar->clear;

            subtest "Plugin $test tests" => $dispatch{$test};
        }
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

#------------------------------------------------------------------------------
#
#  authenticate_user
#
#------------------------------------------------------------------------------

sub _authenticate_user {
    my ($res, $data, $logs);

    # no args

    $trap->read;
    $res = post('/authenticate_user');
    ok $res->is_success, "/authenticate_user with no params is_success";
    cmp_deeply YAML::Load( $res->content ), [ 0, undef ],
      "... and returns expected response";
    cmp_deeply $trap->read,
      superbagof(
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'before_authenticate_user{"password":null,"realm":null,"username":null}'
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'after_authenticate_user{"errors":[],"password":null,"realm":null,"success":0,"username":null}'
        }
      ),
      "... and we see expected hook output in logs.";

    # empty username and password

    $res = post('/authenticate_user',[username=>'',password=>'']);
    ok $res->is_success,
      "/authenticate_user with empty username and password is_success";
    cmp_deeply YAML::Load( $res->content ), [ 0, undef ],
      "... and returns expected response";
    cmp_deeply $trap->read,
      superbagof(
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'before_authenticate_user{"password":"","realm":null,"username":""}'
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'after_authenticate_user{"errors":[],"password":"","realm":null,"success":0,"username":""}'
        }
      ),
      "... and we see expected hook output in logs.";

    # good username, bad password and no realm

    $res = post('/authenticate_user',[username=>'dave',password=>'badpwd']);
    ok $res->is_success,
      "/authenticate_user with user dave, bad password and no realm success";
    cmp_deeply YAML::Load( $res->content ), [ 0, undef ],
      "... and returns expected response";
    $logs = $trap->read;
    cmp_deeply $logs,
      superbagof(
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'before_authenticate_user{"password":"badpwd","realm":null,"username":"dave"}'
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+dave.+realm config2/)
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+dave.+realm config3/)
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+dave.+realm config1/)
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'after_authenticate_user{"errors":[],"password":"badpwd","realm":null,"success":0,"username":"dave"}'
        }
      ),
      "... and we see expected hook output in logs and realms checked."
      or diag explain $logs;

    # good username, good password but wrong realm

    $res = post( '/authenticate_user',
        [ username => 'dave', password => 'beer', realm => 'config2' ] );
    ok $res->is_success,
      "/authenticate_user with user dave, good password but wrong realm success";
    cmp_deeply YAML::Load( $res->content ), [ 0, undef ],
      "... and returns expected response";

    $logs = $trap->read;
    cmp_deeply $logs,
      superbagof(
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'before_authenticate_user{"password":"beer","realm":"config2","username":"dave"}'
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+dave.+realm config2/)
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'after_authenticate_user{"errors":[],"password":"beer","realm":null,"success":0,"username":"dave"}'
        }
      ),
      "... and we see expected hook output in logs and realm config2 checked"
      or diag explain $logs;

    cmp_deeply $logs,
      noneof(
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+dave.+realm config1/)
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+dave.+realm config3/)
        },
      ),
      "... and the other realms were not checked."
      or diag explain $logs;

    # good username, good password and good realm

    $res = post( '/authenticate_user',
        [ username => 'dave', password => 'beer', realm => 'config1' ] );
    ok $res->is_success,
      "/authenticate_user with user dave, good password and good realm success";
    cmp_deeply YAML::Load( $res->content ), [ 1, "config1" ],
      "... and returns expected response";

    $logs = $trap->read;
    cmp_deeply $logs,
      superbagof(
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'before_authenticate_user{"password":"beer","realm":"config1","username":"dave"}'
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+dave.+realm config1/)
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/config1 accepted user dave/),
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'after_authenticate_user{"errors":[],"password":"beer","realm":"config1","success":1,"username":"dave"}'
        }
      ),
      "... and we see expected hook output in logs and only one realm checked"
      or diag explain $logs;

    cmp_deeply $logs,
      noneof(
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+dave.+realm config2/)
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+dave.+realm config3/)
        },
      ),
      "... and the other realms were not checked."
      or diag explain $logs;

    # good username, good password and no realm

    $res = post( '/authenticate_user',
        [ username => 'dave', password => 'beer' ] );
    ok $res->is_success,
      "/authenticate_user with user dave, good password and no realm success";
    cmp_deeply YAML::Load( $res->content ), [ 1, "config1" ],
      "... and returns expected response";

    $logs = $trap->read;
    cmp_deeply $logs,
      superbagof(
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'before_authenticate_user{"password":"beer","realm":null,"username":"dave"}'
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+dave.+realm config2/)
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+dave.+realm config3/)
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+dave.+realm config1/)
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/config1 accepted user dave/),
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'after_authenticate_user{"errors":[],"password":"beer","realm":"config1","success":1,"username":"dave"}'
        }
      ),
      "... and we see expected hook output in logs and 3 realms checked."
      or diag explain $logs;

    # good username, good password and no realm using 2nd realm by priority

    $res = post( '/authenticate_user',
        [ username => 'bananarepublic', password => 'whatever' ] );
    ok $res->is_success,
      "/authenticate_user with user bananarepublic, good password and no realm success";
    cmp_deeply YAML::Load( $res->content ), [ 1, "config3" ],
      "... and returns expected response";

    $logs = $trap->read;
    cmp_deeply $logs,
      superbagof(
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'before_authenticate_user{"password":"whatever","realm":null,"username":"bananarepublic"}'
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+bananarepublic.+realm config2/)
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+bananarepublic.+realm config3/)
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/config3 accepted user bananarepublic/),
        },
        {
            formatted => ignore(),
            level     => 'debug',
            message => 'after_authenticate_user{"errors":[],"password":"whatever","realm":"config3","success":1,"username":"bananarepublic"}'
        }
      ),
      "... and we see expected hook output in logs and 2 realms checked"
      or diag explain $logs;

    cmp_deeply $logs,
      noneof(
        {
            formatted => ignore(),
            level     => 'debug',
            message   => re(qr/Attempting.+bananarepublic.+realm config1/)
        },
      ),
      "... and we don't see realm config1 checked."
      or diag explain $logs;

    # quick pairwise for coverage
    foreach my $username ( undef, +{}, '', 'username' ) {
        foreach my $password ( undef, +{}, '', 'password' ) {
            $res = post( '/authenticate_user',
                [ username => $username, password => $password ] );
            ok $res->is_success, "/authenticate_user with user dave, bad password and no realm success";
            cmp_deeply YAML::Load( $res->content ), [ 0, undef ],
              "... and returns expected response";
        }
    }
}

#------------------------------------------------------------------------------
#
#  create_user
#
#------------------------------------------------------------------------------

sub _create_user {
    my ( $res, $logs );

    # create user with no args should die since we have > 1 realm

    $trap->read;

    $res = post('/create_user');
    is $res->code, 500,
      "/create_user with no params is 500 due to > 1 realm.";

    $logs = $trap->read;
    cmp_deeply $logs,
      [
        {
            formatted => ignore(),
            level     => 'error',
            message   => re(
                qr/Realm must be specified when more than one realm configured/
            ),
        }
      ],
      "... and error about needing realm was logged.";

    # create user with no password

    $res = post( "/create_user",
        [ username => 'createusernopw', realm => 'config1' ] );
    ok $res->is_success, "/create_user with no password is_success";

    for my $realm (qw/config1 config2/) {

        # create a user

        my $data = [
            username => 'newuser',
            password => "pish_$realm",
            realm    => $realm,
        ];

        $res = post( "/create_user", $data );
        ok $res->is_success, "/create_user newuser in realm $realm is success"
          or diag explain $trap->read;
        is $res->content, 1, "... and response content shows create success";

        $logs = $trap->read;
        cmp_deeply $logs,
          superbagof(
            {
                formatted => ignore(),
                level   => 'debug',
                message => qq(before_create_user{"password":"pish_$realm","realm":"$realm","username":"newuser"}),
            },
            {
                formatted => ignore(),
                level     => 'debug',
                message   => 'after_create_user,newuser,1,no',
            }
          ),
          "... and we see expected before/after hook logs.";

        # try creating same user a second time

        $res = post( "/create_user", $data );
        ok $res->is_success,
          "/create_user newuser *again* in realm $realm is success"
          or diag explain $trap->read;
        is $res->content, 0, "... and response content shows create failed";

        $logs = $trap->read;
        cmp_deeply $logs,
          superbagof(
            {
                formatted => ignore(),
                level   => 'debug',
                message => qq(before_create_user{"password":"pish_$realm","realm":"$realm","username":"newuser"}),
            },
            {
                formatted => ignore(),
                level     => 'error',
                message   => re(qr/$realm provider threw error/),
            },
            {
                formatted => ignore(),
                level     => 'debug',
                message   => re(qr/after_create_user,newuser,0,yes/),
            }
          ),
          "... and we see expected before/after hook logs."
          or diag explain $logs;

        # Then try logging in with that user

        $trap->read;    # clear logs

        $res = post( '/login', $data );

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
          "... and we see expected message in logs."
          or diag explain $res;

        is get('/loggedin')->content, "You are logged in",
          "... and checking /loggedin route shows we are logged in";

        get('/logout');
    }

    # create user with `email_welcome` so we can test reset code

    $res = post(
        "/create_user",
        [
            username      => 'newuserwithcode',
            realm         => 'config1',
            email_welcome => 1,
        ]
    );

    is $res->code, 200, "/create_user with welcome_send=>1 response is 200"
      or diag explain $trap->read;

    # the args passed to 'welcome_send' sub
    my $args = $Dancer2::Plugin::Auth::Extensible::Test::App::data;
    like $args->{code}, qr/^\w{32}$/,
      "... and we have a reset code in the email";
}

#------------------------------------------------------------------------------
#
#  get_user_details
#
#------------------------------------------------------------------------------

sub _get_user_details {
    my ( $logs, $res );

    # no args

    $res = post('/get_user_details');
    ok $res->is_success, "/get_user_details with no params is_success";
    is $res->content, 0, "... and no user was returned.";

    # unknown user

    $trap->read;

    $res = post( '/get_user_details', [ username => 'NoSuchUser' ] );
    ok $res->is_success, "/get_user_details with unknown user is_success";
    is $res->content, 0, "... and no user was returned.";

    $logs = $trap->read;
    cmp_deeply $logs, superbagof(
        {
            formatted => ignore(),
            level => 'debug',
            message => 'Attempting to find user NoSuchUser in realm config2',
        },
        {
            formatted => ignore(),
            level => 'debug',
            message => 'Attempting to find user NoSuchUser in realm config3',
        },
        {
            formatted => ignore(),
            level => 'debug',
            message => 'Attempting to find user NoSuchUser in realm config1',
        },
    ), "... and we see logs we expect."
        or diag explain $logs;

    # known user but wrong realm

    $trap->read;

    $res =
      post( '/get_user_details', [ username => 'dave', realm => 'config2' ] );
    ok $res->is_success, "/get_user_details dave config2 is_success";
    is $res->content, 0, "... and no user was returned (wrong realm).";

    $logs = $trap->read;
    cmp_deeply $logs, superbagof(
        {
            formatted => ignore(),
            level => 'debug',
            message => 'Attempting to find user dave in realm config2',
        },
    ), "... and we see logs we expect" or diag explain $logs;

    cmp_deeply $logs, noneof(
        {
            formatted => ignore(),
            level => 'debug',
            message => 'Attempting to find user dave in realm config3',
        },
        {
            formatted => ignore(),
            level => 'debug',
            message => 'Attempting to find user dave in realm config1',
        },
    ), "... and none of the ones we don't expect." or diag explain $logs;

    # known user unspecified realm

    $trap->read;

    $res =
      post( '/get_user_details', [ username => 'dave' ] );
    ok $res->is_success, "/get_user_details dave in any realm is_success";
    like $res->content, qr/David Precious/,
      "... and correct user was returned.";

    # known user correct realm

    $trap->read;

    $res =
      post( '/get_user_details', [ username => 'dave', realm => 'config1' ] );
    ok $res->is_success, "/get_user_details dave in config1 is_success";
    like $res->content, qr/David Precious/,
      "... and correct user was returned.";

};

#------------------------------------------------------------------------------
#
#  login_logout
#
#  also includes some auth_provider tests
#
#------------------------------------------------------------------------------

sub _login_logout {
    my ( $data, $res, $logs );

    # auth_provider with no args

    $trap->read;
    $res = post('/auth_provider');
    is $res->code, 500, "auth_provider with no args dies";
    $logs = $trap->read;
    cmp_deeply $logs, superbagof(
        { formatted => ignore(),
            level => 'error',
            message => re(qr/auth_provider needs realm or/),
        }
    ), "... and correct error message is seen in logs." or diag explain $logs;

    # auth_provider with non-existant realm

    $trap->read;
    $res = post('/auth_provider', [realm => 'NoSuchRealm']);
    is $res->code, 500, "auth_provider with non-existant realm dies";
    $logs = $trap->read;
    cmp_deeply $logs, superbagof(
        { formatted => ignore(),
            level => 'error',
            message => re(qr/Invalid realm NoSuchRealm/),
        }
    ), "... and correct error message is seen in logs." or diag explain $logs;

    # auth_provider with good realm

    $res = post('/auth_provider', [realm => 'config1']);
    ok $res->is_success, "auth_provider with good realm lives"
      or diag explain $trap->read;

    # Check that login route doesn't match any request string with '/login'.

    $trap->read;
    $res = get('/foo/login');
    is $res->code, 404, "'/foo/login' URL not matched by login route regex."
      or diag explain $trap->read;

    # Now, without being logged in, check we can access the index page,
    # but not stuff we need to be logged in for:

    $res = get('/');
    ok $res->is_success, "Index always accessible - GET / success";
    is $res->content,    'Index always accessible',
          "...and we got expected content.";

    # check session_data when not logged in

    $res = get('/session_data');
    ok $res->is_success, "/session_data is_success";
    $data = YAML::Load $res->content;
    ok !defined $data->{logged_in_user},
      "... and logged_in_user is not set in the session";
    ok !defined $data->{logged_in_user_realm},
      "... and logged_in_user_realm is not set in the session.";

    # get /login

    $res = get('/login');
    TODO: {
        local $TODO = "GET /login returns 401";
        ok $res->is_success, "GET /login is_success";
    }
    like $res->content, qr/input.+name="password"/,
      "... and we have the login page.";
    like $res->content,
      qr/Enter your username to obtain an email to reset your password/,
      "... which has password reset option (reset_password_handler=>1).";

    # post empty /login

    $res = post('/login');
    TODO: {
        local $TODO = "POST /login returns 401 for failed login";
        ok $res->is_success, "POST /login is_success";
    }
    like $res->content, qr/input.+name="password"/,
      "... and we have the login page";
    like $res->content, qr/LOGIN FAILED/,
      "... and we see LOGIN FAILED";

    # check session_data again

    $res = get('/session_data');
    ok $res->is_success, "/session_data is_success";
    $data = YAML::Load $res->content;
    ok !defined $data->{logged_in_user},
      "... and logged_in_user is not set in the session";
    ok !defined $data->{logged_in_user_realm},
      "... and logged_in_user_realm is not set in the session.";

    # post good /login

    $res = post( '/login', [ username => 'dave', password => 'beer' ] );
    ok $res->is_redirect, "POST /login with good username/password is_redirect";
    is $res->header('location'), 'http://localhost/',
      "... and redirect location is correct.";

    # check session_data again

    $res = get('/session_data');
    ok $res->is_success, "/session_data is_success";
    $data = YAML::Load $res->content;
    is $data->{logged_in_user}, 'dave',
      "... and session logged_in_user is set to dave";
    is $data->{logged_in_user_realm}, 'config1',
      "... and session logged_in_user_realm is set to config1.";

    # get /login whilst already logged in

    $res = get('/login');
    ok $res->is_redirect, "GET /login whilst logged in is redirected."
      or diag explain $res;
    is $res->header('location'), 'http://localhost/',
      "... and redirect location is correct.";

    # get /login whilst already logged in with return_url set

    $res = get('/login?return_url=/foo');
    ok $res->is_redirect,
      "GET /login whilst logged in with return_url set in query is redirected.";
    is $res->header('location'), 'http://localhost/foo',
      "... and redirect location is correct.";

    # auth_provider with no realm but user is logged in

    $res = post('/auth_provider');
    ok $res->is_success, "auth_provider with *no* realm lives"
      or diag explain $trap->read;

    # get /logout

    $res = get('/logout');
    ok $res->is_redirect, "GET /logout is_redirect" or diag explain $res;
    is $res->header('location'), 'http://localhost/',
      "... and redirect location is correct.";

    # check session_data again

    $res = get('/session_data');
    ok $res->is_success, "/session_data is_success";
    $data = YAML::Load $res->content;
    ok !defined $data->{logged_in_user},
      "... and logged_in_user is not set in the session";
    ok !defined $data->{logged_in_user_realm},
      "... and logged_in_user_realm is not set in the session.";

    # post good /login

    $res = post( '/login', [ username => 'dave', password => 'beer' ] );
    ok $res->is_redirect, "POST /login with good username/password is_redirect";
    is $res->header('location'), 'http://localhost/',
      "... and redirect location is correct.";

    # check session_data again

    $res = get('/session_data');
    ok $res->is_success, "/session_data is_success";
    $data = YAML::Load $res->content;
    is $data->{logged_in_user}, 'dave',
      "... and session logged_in_user is set to dave" or diag explain $data;
    is $data->{logged_in_user_realm}, 'config1',
      "... and session logged_in_user_realm is set to config1.";

    # POST /logout

    $res = post('/logout');
    ok $res->is_redirect, "POST /logout is_redirect" or diag explain $res;
    is $res->header('location'), 'http://localhost/',
      "... and redirect location is correct.";

    # check session_data again

    $res = get('/session_data');
    ok $res->is_success, "/session_data is_success";
    $data = YAML::Load $res->content;
    ok !defined $data->{logged_in_user},
      "... and logged_in_user is not set in the session";
    ok !defined $data->{logged_in_user_realm},
      "... and logged_in_user_realm is not set in the session.";

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

    # /login/denied page

    {
        my $res = get('/login/denied');
        is $res->code, '403', "GET /login/denied results in a 403 denied code";
        like $res->content, qr/Permission Denied/,
          "... and we have Permission Denied text in page";
    }
}

#------------------------------------------------------------------------------
#
#  logged_in_user
#
#------------------------------------------------------------------------------

sub _logged_in_user {
    my ( $data, $res );

    # check logged_in_user when not logged in

    $res = get('/logged_in_user');
    ok $res->is_success, "/logged_in_user is_success";
    $data = YAML::Load $res->content;
    is $data, 'none', "... and there is no logged_in_user."
      or diag explain $data;

    # post empty /login

    $res = post('/login');
    TODO: {
        local $TODO = "POST /login returns 401 for failed login";
        ok $res->is_success, "POST /login is_success";
    }
    like $res->content, qr/input.+name="password"/,
      "... and we have the login page";
    like $res->content, qr/LOGIN FAILED/,
      "... and we see LOGIN FAILED";

    # check logged_in_user again

    $res = get('/logged_in_user');
    ok $res->is_success, "/logged_in_user is_success";
    $data = YAML::Load $res->content;
    is $data, 'none', "... and there is no logged_in_user."
      or diag explain $data;

    # post good /login

    $res = post( '/login', [ username => 'dave', password => 'beer' ] );
    ok $res->is_redirect, "POST /login with good username/password is_redirect";
    is $res->header('location'), 'http://localhost/',
      "... and redirect location is correct.";

    # check logged_in_user again

    $res = get('/logged_in_user');
    ok $res->is_success, "/logged_in_user is_success";
    $data = YAML::Load $res->content;
    is $data->{name}, 'David Precious',
      "... and we see dave's name is David Precious." or diag explain $data;

    # get /logout

    $res = get('/logout');
    ok $res->is_redirect, "GET /logout is_redirect" or diag explain $res;
    is $res->header('location'), 'http://localhost/',
      "... and redirect location is correct.";

    # check logged_in_user again

    $res = get('/logged_in_user');
    ok $res->is_success, "/logged_in_user is_success";
    $data = YAML::Load $res->content;
    is $data, 'none', "... and there is no logged_in_user."
      or diag explain $data;
}

#------------------------------------------------------------------------------
#
#  logged_in_user_lastlogin
#
#------------------------------------------------------------------------------

sub _logged_in_user_lastlogin {
    my ( $res, $session );

    # create a new user for test so we are sure lastlogin has not been set

    $res = post(
        "/create_user",
        [
            username      => 'lastlogin1',
            password      => 'lastlogin2',
            realm         => 'config1',
        ]
    );
    ok $res->is_success, "create_user lastlogin1 call is_success";

    # check the session for logged_in_user_lastlogin

    $res = get('/session_data');
    ok $res->is_success, "get /session_data is_success";
    $session = YAML::Load $res->content;
    ok !defined $session->{logged_in_user_lastlogin},
      "... and logged_in_user_lastlogin is not set in the session.";

    # we cannot reach require_login routes

    $res = get('/loggedin');
    ok $res->is_redirect, "GET /loggedin causes redirect";
    is $res->header('location'),
      'http://localhost/login?return_url=%2Floggedin',
      "... and we're redirected to /login with return_url=/loggedin.";

    # login

    $res =
      post( '/login', [ username => 'lastlogin1', password => 'lastlogin2' ] );
    ok $res->is_redirect, "POST /login with with new user is_redirect";
    is $res->header('location'), 'http://localhost/',
      "... and redirect location is correct.";

    # check we can reach restricted page

    $res = get('/loggedin');
    ok $res->is_success, "GET /loggedin is_success now we're logged in";
    is $res->content, "You are logged in", "... and we can see page content.";

    # check the session for logged_in_user_lastlogin

    $res = get('/session_data');
    ok $res->is_success, "get /session_data is_success";
    $session = YAML::Load $res->content;
    ok !defined $session->{logged_in_user_lastlogin},
      "... and logged_in_user_lastlogin is still not set in the session.";

    # check logged_in_user_lastlogin method

    $res = get('/logged_in_user_lastlogin');
    ok $res->is_success, "get /logged_in_user_lastlogin is_success";
    is $res->content, "not set",
      "... and logged_in_user_lastlogin returns undef"
      or diag explain $res->content;

    # logout

    $res = get('/logout');
    ok $res->is_redirect, "/logout is_success";

    # login again and now logged_in_user_lastlogin should be set

    $res =
      post( '/login', [ username => 'lastlogin1', password => 'lastlogin2' ] );
    ok $res->is_redirect, "POST /login with with new user is_redirect";
    is $res->header('location'), 'http://localhost/',
      "... and redirect location is correct.";

    # check we can reach restricted page

    $res = get('/loggedin');
    ok $res->is_success, "GET /loggedin is_success now we're logged in";
    is $res->content, "You are logged in", "... and we can see page content.";

    # check the session for logged_in_user_lastlogin

    $res = get('/session_data');
    ok $res->is_success, "get /session_data is_success";
    $session = YAML::Load $res->content;
    ok defined $session->{logged_in_user_lastlogin},
      "... and logged_in_user_lastlogin is still not set in the session."
      or diag explain $session;
    like $session->{logged_in_user_lastlogin}, qr/^\d+$/,
      "... and session logged_in_user_lastlogin looks like an epoch time.";

    # check logged_in_user_lastlogin method

    $res = get('/logged_in_user_lastlogin');
    ok $res->is_success, "get /logged_in_user_lastlogin is_success";
    my $date = DateTime->now->ymd;
    is $res->content, $date,
      "... and logged_in_user_lastlogin is $date.";

    # cleanup
    get('/logout');
}

#------------------------------------------------------------------------------
#
#  logged_in_user_password_expired
#
#------------------------------------------------------------------------------

sub _logged_in_user_password_expired {
    ok 1;
}

#------------------------------------------------------------------------------
#
#  password_reset
#
#------------------------------------------------------------------------------

sub _password_reset {
    my $res;

    $res = get('/login');
    ok 1;
}

#------------------------------------------------------------------------------
#
#  password_reset_send
#
#------------------------------------------------------------------------------

sub _password_reset_send {
    ok 1;
}

#------------------------------------------------------------------------------
#
#  require_login
#
#------------------------------------------------------------------------------

sub _require_login {
    my ( $res, $logs );

    # check open / is ok

    $res = get('/');
    ok $res->is_success, "GET / is success - no login required";

    # we cannot reach require_login routes

    $res = get('/loggedin');
    ok $res->is_redirect, "GET /loggedin causes redirect";
    is $res->header('location'),
      'http://localhost/login?return_url=%2Floggedin',
      "... and we're redirected to /login with return_url=/loggedin.";

    # regex route when not logged in

    $res = get('/regex/a');
    ok $res->is_redirect, "GET /regex/a causes redirect";
    is $res->header('location'),
      'http://localhost/login?return_url=%2Fregex%2Fa',
      "... and we're redirected to /login with return_url=/regex/a.";

    # login

    $res = post( '/login', [ username => 'dave', password => 'beer' ] );
    ok $res->is_redirect, "POST /login with good username/password is_redirect";
    is $res->header('location'), 'http://localhost/',
      "... and redirect location is correct.";

    # check we can reach restricted page

    $res = get('/loggedin');
    ok $res->is_success, "GET /loggedin is_success now we're logged in";
    is $res->content, "You are logged in", "... and we can see page content.";

    # regex route

    $res = get('/regex/a');
    ok $res->is_success, "GET /regex/a is_success now we're logged in";
    is $res->content, "Matched", "... and we can see page content.";

    # cleanup
    get('/logout');

    # require_login should receive a coderef

    $trap->read;    # clear logs
    $res  = get('/require_login_no_sub');
    $logs = $trap->read;
    is @$logs, 1, "One message in the logs" or diag explain $logs;
    is $logs->[0]->{level}, 'warning', "We got a warning in the logs";
    is $logs->[0]->{message},
      'Invalid require_login usage, please see docs',
      "Warning message is as expected";
    $trap->read;    # clear logs

    $res  = get('/require_login_not_coderef');
    $logs = $trap->read;
    is @$logs, 1, "One message in the logs" or diag explain $logs;
    is $logs->[0]->{level}, 'warning', "We got a warning in the logs";
    is $logs->[0]->{message},
      'Invalid require_login usage, please see docs',
      "Warning message is as expected";
}

#------------------------------------------------------------------------------
#
#  roles
#
#------------------------------------------------------------------------------

sub _roles {

    # make sure we're not logged in

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

    # and can't reach pages that have require_role

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

    # ... and that we can log in with real details

    {
        $trap->read;    # clear logs

        my $res = post( '/login', [ username => 'dave', password => 'beer' ] );

        is( $res->code, 302, 'Login with real details succeeds' )
          or diag explain $trap->read;

        is get('/loggedin')->content, "You are logged in",
          "... and checking /loggedin route shows we are logged in";
    }

    # user_roles for logged_in_user

    {
        $trap->read;    # clear logs

        my $res = get('/roles');

        is( $res->code, 200, 'get /roles is 200' )
          or diag explain $trap->read;

        is( $res->content, 'BeerDrinker,Motorcyclist',
            'Correct roles for logged in user' );
    }

    # user_roles for specific user

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
            "We can request a multi-role route requiring with any one role" )
          or diag explain $trap->read;
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

    # 2 arg user_has_role

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

    {
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

    {
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

}

#------------------------------------------------------------------------------
#
#  update_current_user
#
#------------------------------------------------------------------------------

sub _update_current_user {
    for my $realm (qw/config1 config2/) {

        # Now we're going to update the current user

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

            $res = post('/logout');
        }
    }
}

#------------------------------------------------------------------------------
#
#  update_user
#
#------------------------------------------------------------------------------

sub _update_user {
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

#------------------------------------------------------------------------------
#
#  user_password
#
#------------------------------------------------------------------------------

sub _user_password {
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

    # now with logged_in_user

    {
        $trap->read;    # clear logs

        my $res = post( '/login', [ username => 'dave', password => 'beer' ] );

        is( $res->code, 302, 'Login with real details succeeds' )
          or diag explain $trap->read;

        is get('/loggedin')->content, "You are logged in",
          "... and checking /loggedin route shows we are logged in";
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

    # cleanup
    get('/logout');
}

1;
