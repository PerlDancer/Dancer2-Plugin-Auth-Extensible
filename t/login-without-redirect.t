use strict;
use warnings;

use Test::More;
use Plack::Test;
use HTTP::Request::Common;
use HTTP::Cookies;

BEGIN {
    $ENV{DANCER_CONFDIR}     = 't/lib';
    $ENV{DANCER_ENVIRONMENT} = 'login-without-redirect';
    $ENV{DANCER_VIEWS}       = 't/lib/views/login-without-redirect';
}

{
    package TestApp;
    use lib 't/lib';
    use Dancer2;
    use Dancer2::Plugin::Auth::Extensible;

    set logger => 'capture';
    set log    => 'debug';

    get '/use_custom_login_template' => sub {
        my $plugin = app->with_plugin('Auth::Extensible');
        $plugin->{login_template} = 'custom_login';
    };
    get '/use_builtin_login_template' => sub {
        my $plugin = app->with_plugin('Auth::Extensible');
        $plugin->{login_template} = 'login';
    };
    get '/loggedin' => require_login sub {
        "You are logged in";
    };
    post '/protected_post' => require_login sub {
        my $params = params;
        send_as YAML => [ "You are logged in", $params ];
    };
    get '/beer' => require_role BeerDrinker => sub {
        "Have some beer";
    };
    get '/cider' => require_role CiderDrinker => sub {
        "Have some cider";
    };
}

my $app = Dancer2->runner->psgi_app;
is( ref $app, 'CODE', 'Got app' );

my $test = Plack::Test->create($app);
my $trap = TestApp->dancer_app->logger_engine->trapper;
my $url  = 'http://localhost';
my $jar  = HTTP::Cookies->new();

{
    # WWW-Authenticate robot header

    my $req = GET "$url/loggedin";
    $jar->add_cookie_header($req);
    my $res = $test->request( $req );
    $jar->extract_cookies($res);

    is $res->code, 401,
      "Trying a require_login page with *no* User-Agent header gets 401";
    like $res->header('www-authenticate'), qr/Basic realm=/,
      "... and we have a WWW-Authenticate header with Basic realm";
    like $res->content, qr/You need to log in to continue/,
      "... and we can see a login form";
    like $res->content, qr/input.+name="__auth_extensible_username/,
      "... and we see __auth_extensible_username field";
    like $res->content, qr/This text is in the layout/,
      "... and the response is wrapped in the layout.";
}
{
    # WWW-Authenticate real user (non-robot) header

    my $req = GET "$url/loggedin",
        'User-Agent' => 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.1 (KHTML like Gecko) Chrome/21.0.1180.83 Safari/537.1';
    $jar->add_cookie_header($req);
    my $res = $test->request( $req );
    $jar->extract_cookies($res);

    is $res->code, 401,
      "Trying a require_login page with real User-Agent header gets 401";
    like $res->header('www-authenticate'), qr/FormBased.+use form to log in/,
      "... and we have a WWW-Authenticate header which says use the form";
    like $res->content, qr/You need to log in to continue/,
      "... and we can see a login form";
    like $res->content, qr/input.+name="__auth_extensible_username/,
      "... and we see __auth_extensible_username field";
    like $res->content, qr/This text is in the layout/,
      "... and the response is wrapped in the layout.";

}
{
    # cutom login_template

    $test->request(GET '/use_custom_login_template');

    my $req = GET "$url/loggedin";
    $jar->add_cookie_header($req);
    my $res = $test->request( $req );
    $jar->extract_cookies($res);

    is $res->code, 401,
      "Trying a require_login page with custom login_template gets 401";
    like $res->header('www-authenticate'), qr/Basic realm=/,
      "... and we have a WWW-Authenticate header with Basic realm";
    like $res->content, qr/Custom Login Page/,
      "... and we can see our custom login form";
    like $res->content, qr/input.+name="__auth_extensible_username/,
      "... and we see __auth_extensible_username field";
    like $res->content, qr/This text is in the layout/,
      "... and the response is wrapped in the layout.";

    $test->request(GET '/use_builtin_login_template');

}
{
    # bad login

    $trap->read;
    my $req =
      POST "$url/loggedin",
      [
        __auth_extensible_username => 'dave',
        __auth_extensible_password => 'cider',
      ];
    $jar->add_cookie_header($req);
    my $res = $test->request( $req );
    $jar->extract_cookies($res);

    is $res->code, 401,
      "Try posting bad login details to a require_login page gets 401 response"
          or diag explain $trap->read;
    like $res->content, qr/You need to log in to continue/,
      "... and we can see a login form";
    like $res->content, qr/LOGIN FAILED/,
      "... and we see LOGIN FAILED";
    like $res->content, qr/input.+name="__auth_extensible_username/,
      "... and we see __auth_extensible_username field";
    like $res->content, qr/This text is in the layout/,
      "... and the response is wrapped in the layout.";
}
{
    # good login

    $trap->read;
    my $req =
      POST "$url/loggedin",
      [
        __auth_extensible_username => 'dave',
        __auth_extensible_password => 'beer',
      ];
    $jar->add_cookie_header($req);
    my $res = $test->request( $req );
    $jar->extract_cookies($res);

    ok $res->is_success,
      "Try posting real login details to a require_login page is_success"
          or diag explain $trap->read;
    is $res->content, "You are logged in",
      "... and we see the real page content." or diag explain $trap->read;

    # logout
    $req = GET '/logout';
    $jar->add_cookie_header($req);
    $test->request( $req );
}
done_testing;
__END__
{
    my $req = GET "$url/beer", %ua;
    $jar->add_cookie_header($req);
    my $res = $test->request( $req );
    $jar->extract_cookies($res);

    is $res->code, 401,
      "Trying a require_role page gets 401 response";
    like $res->header('www-authenticate'), qr/FormBased.+use form to log in/,
      "... and we have a WWW-Authenticate header which says use the form";
    like $res->content, qr/You need to log in to continue/,
      "... and we can see a login form";
    like $res->content, qr/input.+name="__auth_extensible_username/,
      "... and we see __auth_extensible_username field.";

}
    like $res->header('www-authenticate'), qr/Basic realm=/,
      "... and we have a WWW-Authenticate header with Basic realm";
    like $res->content, qr/You need to log in to continue/,
      "... and we can see a login form";
    like $res->content, qr/input.+name="__auth_extensible_username/,
      "... and we see __auth_extensible_username field.";
}
done_testing;
__END__
{
    my $req = POST "$url/login", [ username => 'dave', password => 'bad' ];
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    ok $res->is_success, "POST /login with bad password response is OK";
    is $res->content, "Not allowed", "... and we see our custom response.";
}
{
    my $req = GET "$url/loggedin";
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    ok $res->is_redirect, "... and we still cannot reach protected page.";
}
{
    my $req = POST "$url/login", [ username => 'dave', password => 'beer' ];
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    ok $res->is_success, "POST /login with good password response is OK";
    is $res->content, "Welcome!", "... and we see our custom response";
}
{
    my $req = GET "$url/loggedin";
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    ok $res->is_success, "... and we can reach protected page";
    is $res->content,    "You are logged in",
      "... which has the content we expect.";
}
{
    my $req = GET "$url/logout";
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    ok $res->is_success, "/logout is successful";
}
{
    my $req = GET "$url/loggedin";
    $jar->add_cookie_header($req);
    my $res = $test->request($req);
    ok $res->is_redirect, "... and we can no longer reach protected page.";
}

done_testing;
