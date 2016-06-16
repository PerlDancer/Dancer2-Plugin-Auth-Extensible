package Dancer2::Plugin::Auth::Extensible;

our $VERSION = '0.600';

use strict;
use warnings;
use Carp;
use Dancer2::Core::Types qw(Bool HashRef Str);
use Module::Runtime qw(use_module);
use Session::Token;
use Try::Tiny;
use Dancer2::Plugin;

#
# config attributes
#

has denied_page => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '/login/denied' },
);

has disable_roles => (
    is          => 'ro',
    isa         => Bool,
    from_config => 1,
    default     => sub { 0 },
);

has exit_page => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '/' },
);

has login_page => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '/login' },
);

has login_page_handler => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '_default_login_page' },
);

has logout_page => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '/logout' },
);

has no_login_handler => (
    is          => 'ro',
    isa         => Bool,
    from_config => 1,
    default     => sub { 0 },
);

has mailer => (
    is          => 'ro',
    isa         => HashRef,
    from_config => 1,
    default     => sub { '' },
);

has mail_from => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '' },
);

has no_default_pages => (
    is          => 'ro',
    isa         => Bool,
    from_config => 1,
    default     => sub { 0 },
);

has password_generator => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '_default_password_generator' },
);

has password_reset_send_email => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '_default_email_password_reset' },
);

has password_reset_text => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '' },
);

has permission_denied_handler => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '_default_permission_denied_handler' },
);

has permission_denied_page_handler => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '_default_permission_denied_page' },
);

has realms => (
    is          => 'ro',
    isa         => HashRef,
    from_config => 1,
    default     => sub { {} },
);

has record_lastlogin => (
    is          => 'ro',
    isa         => Bool,
    from_config => 1,
    default     => sub { 0 },
);

has reset_password_handler => (
    is          => 'ro',
    isa         => Bool,
    from_config => 1,
    default     => sub { 0 },
    plugin_keyword => 1,
);

has user_home_page => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '/' },
);

has welcome_send => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '_default_welcome_send' },
);

has welcome_text => (
    is          => 'ro',
    isa         => Str,
    from_config => 1,
    default     => sub { '' },
);

#
# other attributes
#

has realm_providers => (
    is       => 'ro',
    isa      => HashRef,
    default  => sub { {} },
    init_arg => undef,
);

#
# hooks
#

plugin_hooks qw(login_required permission_denied);

#
# keywords
#

plugin_keywords 'authenticate_user', 'create_user', 'get_user_details',
  'logged_in_user',                  'logged_in_user_lastlogin',
  'logged_in_user_password_expired', 'password_reset_send',
  [ 'require_all_roles', 'requires_all_roles' ],
  [ 'require_any_role',  'requires_any_role' ],
  [ 'require_login',     'requires_login' ],
  [ 'require_role',      'requires_role' ],
  'update_current_user', 'update_user', 'user_has_role', 'user_password',
  'user_roles';

#
# public methods
#

sub BUILD {
    my $plugin = shift;
    my $app    = $plugin->app;

    my @realms = keys %{ $plugin->realms }
      or warn
      "No Auth::Extensible realms configured with which to authenticate user";

    # Force all providers to load whilst we have access to the full dsl.
    # If we try and load later, then if the provider is using other
    # keywords (such as schema) they will not be available from the dsl.
    for my $realm (@realms) {
        $plugin->auth_provider($realm);
    }

    if ( !$plugin->no_default_pages ) {

        my $login_page  = $plugin->login_page;
        my $denied_page = $plugin->denied_page;

        # Match optional reset code, but not "denied"
        $app->add_route(
            method => 'get',
            regexp => qr!^$login_page/?([\w]{32})?$!,
            code   => sub {
                my $app = shift;

                if ( $plugin->logged_in_user ) {
                    $app->redirect( $app->request->params->{return_url}
                          || $plugin->user_home_page );
                }

                # Reset password code submitted?
                my ($code) = $app->request->splat;

                if (   $plugin->reset_password_handler
                    && $plugin->user_password(code => $code ) )
                {
                    $app->request->params->{password_code_valid} = 1;
                }
                else {
                    $app->response->status(401);
                }

                no strict 'refs';
                return &{ $plugin->login_page_handler }($plugin);
            },
        );

        $app->add_route(
            method => 'get',
            regexp => qr!^$denied_page$!,
            code   => sub {
                my $app = shift;
                $app->response->status(403);
                no strict 'refs';
                return &{ $plugin->permission_denied_page_handler }($plugin);
            },
        );
    }

    if ( !$plugin->no_login_handler ) {

        my $login_page  = $plugin->login_page;
        my $logout_page = $plugin->logout_page;

        # Match optional reset code, but not "denied"
        $app->add_route(
            method => 'post',
            regexp => qr!^$login_page/?([\w]{32})?$!,
            code   => \&_post_login_route,
        );

        for my $method (qw/get post/) {
            $app->add_route(
                method => $method,
                regexp => qr!^$logout_page$!,
                code   => \&_logout_route,
            );
        }
    }
}

sub auth_provider {
    my ( $plugin, $realm ) = @_;

    # If no realm was provided, but we have a logged in user, use their realm.
    # Don't try and read the session any earlier though, as it won't be
    # available on plugin load
    if ( !$realm && $plugin->app->session->read('logged_in_user') ) {
        $realm = $plugin->app->session->read('logged_in_user_realm');
    }

    # First, if we already have a provider for this realm, go ahead and use it:
    return $plugin->realm_providers->{$realm}
      if exists $plugin->realm_providers->{$realm};

    # OK, we need to find out what provider this realm uses, and get an instance
    # of that provider, configured with the settings from the realm.
    my $realm_settings = $plugin->realms->{$realm}
      or die "Invalid realm $realm";

    my $provider_class = $realm_settings->{provider}
      or die "No provider configured - consult documentation for "
      . __PACKAGE__;

    if ( $provider_class !~ /::/ ) {
        $provider_class = __PACKAGE__ . "::Provider::$provider_class";
    }

    return $plugin->realm_providers->{$realm} =
      use_module($provider_class)->new(
        plugin => $plugin,
        %$realm_settings,
      );
}

sub authenticate_user {
    my ( $plugin, $username, $password, $realm ) = @_;

    my @realms_to_check = $realm ? ($realm) : ( keys %{ $plugin->realms } );

    for my $realm (@realms_to_check) {
        $plugin->app->log( debug =>
              "Attempting to authenticate $username against realm $realm" );
        my $provider = $plugin->auth_provider($realm);
        my %lastlogin =
          $plugin->record_lastlogin
          ? ( lastlogin => 'logged_in_user_lastlogin' )
          : ();
        if ( $provider->authenticate_user( $username, $password, %lastlogin ) )
        {
            $plugin->app->log( debug => "$realm accepted user $username" );
            return wantarray ? ( 1, $realm ) : 1;
        }
    }

    # If we get to here, we failed to authenticate against any realm using the
    # details provided.
    # TODO: allow providers to raise an exception if something failed, and catch
    # that and do something appropriate, rather than just treating it as a
    # failed login.
    return wantarray ? ( 0, undef ) : 0;
}

sub create_user {
    my $plugin  = shift;
    my %options = @_;

    my @all_realms = keys %{ $plugin->realms };
    die "Realm must be specified when more than one realm configured"
      if !$options{realm} && @all_realms > 1;

    my $realm = delete $options{realm} || $all_realms[0];
    my $email_welcome = delete $options{email_welcome};

    my $provider = $plugin->auth_provider($realm);

    # Prevent duplicate users. Would be nice to make this an exception,
    # but that's not in keeping with other functions of this module
    if ( $provider->get_user_details( $options{username} ) ) {
        $plugin->app->log(
            info => "User $options{username} already exists. Not creating." );
        return;
    }
    my $user = $provider->create_user(%options);
    if ($email_welcome) {
        my $code = _reset_code();

        # Would be slightly more efficient to do this at time of creation, but
        # this keeps the code simpler for the provider
        $user = $provider->set_user_details( $user->{username},
            pw_reset_code => $code );
        no strict 'refs';

        # email hard-coded as per password_reset_send()
        my %params = ( code => $code, email => $user->{email}, user => $user );
        &{ $plugin->welcome_send }( $plugin, %params );
    }
    $user;
}

sub get_user_details {
    my ( $plugin, $username, $realm ) = @_;

    my @realms_to_check = $realm ? ($realm) : ( keys %{ $plugin->realms } );

    for my $realm (@realms_to_check) {
        $plugin->app->log(
            debug => "Attempting to find user $username in realm $realm" );
        my $provider = $plugin->auth_provider($realm);
        my $user = $provider->get_user_details( $username, $realm );
        $user and return $user;
    }
}

sub logged_in_user {
    my $plugin  = shift;
    my $app     = $plugin->app;
    my $session = $app->session;
    my $request = $app->request;

    if ( my $user = $session->read('logged_in_user') ) {
        my $existing = $request->vars->{logged_in_user_hash};
        return $existing if $existing;
        my $realm    = $session->read('logged_in_user_realm');
        my $provider = $plugin->auth_provider($realm);
        my $user     = $provider->get_user_details( $user, $realm );
        $request->vars->{logged_in_user_hash} = $user;
        return $user;
    }
    else {
        return;
    }
}

sub logged_in_user_lastlogin {
    shift->app->session->read('logged_in_user_lastlogin');
}

sub logged_in_user_password_expired {
    my $plugin = shift;
    return unless $plugin->logged_in_user;
    my $provider = $plugin->auth_provider;
    $provider->password_expired( $plugin->logged_in_user );
}

sub password_reset_send {
    my ( $plugin, %options ) = @_;

    my $result = 0;

    my @realms_to_check =
      $options{realm}
      ? ( $options{realm} )
      : ( keys %{ $plugin->realms } );

    my $username = $options{username}
      or die "username must be passed to password_reset_send";

    foreach my $realm (@realms_to_check) {
        my $this_result;
        $plugin->app->log( debug =>
              "Attempting to find $username in realm $realm for password reset"
        );
        my $provider = $plugin->auth_provider($realm);

        # Generate random string for the password reset URL
        my $code = _reset_code();
        my $user = try {
            $provider->set_user_details( $username, pw_reset_code => $code );
        }
        catch {
            $plugin->app->log(
                debug => "Failed to set_user_details with $realm: $_" );
        };
        if ($user) {

            # Okay, so email key is hard-coded, and therefore relies on the
            # provider returning that key. The alternative is to have a
            # separate provider function to get an email address, which seems
            # an overkill. Providers can make the email key configurable if
            # need be
            my %options = ( code => $code, email => $user->{email} );

            no strict 'refs';
            $result++
              if &{ $plugin->password_reset_send_email }( $plugin, %options );
        }
    }
    $result ? 1 : 0;    # 1 if at least one send was successful
}

sub require_all_roles {
    return _build_wrapper( @_, 'all' );
}

sub require_any_role {
    return _build_wrapper( @_, 'any' );
}

sub require_login {
    my $plugin  = shift;
    my $coderef = shift;

    return sub {
        if ( !$coderef || ref $coderef ne 'CODE' ) {
            $plugin->app->log(
                warning => "Invalid require_login usage, please see docs" );
        }

        my $user = $plugin->logged_in_user;
        if ( !$user ) {
            $plugin->execute_plugin_hook( 'login_required', $coderef );

            # TODO: see if any code executed by that hook set up a response
            return $plugin->app->redirect(
                $plugin->app->request->uri_for(
                    $plugin->login_page,
                    { return_url => $plugin->app->request->request_uri }
                )
            );
        }
        return $coderef->($plugin);
    };
}

sub require_role {
    return _build_wrapper( @_, 'single' );
}

sub update_current_user {
    my ( $plugin, %update ) = @_;

    my $session = $plugin->app->session;
    if ( my $username = $session->read('logged_in_user') ) {
        my $realm = $session->read('logged_in_user_realm');
        $plugin->update_user( $username, realm => $realm, %update );
    }
    else {
        $plugin->app->log( debug =>
              "Could not update current user as no user currently logged in" );
    }
}

sub update_user {
    my ( $plugin, $username, %update ) = @_;

    my $request = $plugin->app->request;
    my $session = $plugin->app->session;

    my @all_realms = keys %{ $plugin->realms };
    die "Realm must be specified when more than one realm configured"
      if !$update{realm} && @all_realms > 1;

    my $realm    = delete $update{realm} || $all_realms[0];
    my $provider = $plugin->auth_provider($realm);
    my $updated  = $provider->set_user_details( $username, %update );
    my $cur_user = $session->read('logged_in_user');
    $request->vars->{logged_in_user_hash} = $updated
      if $cur_user && $cur_user eq $username;
    $updated;
}

sub user_has_role {
    my $plugin = shift;

    my $session = $plugin->app->session;

    my ( $username, $want_role );
    if ( @_ == 2 ) {
        ( $username, $want_role ) = @_;
    }
    else {
        $username  = $session->read('logged_in_user');
        $want_role = shift;
    }

    return unless defined $username;

    my $roles = $plugin->user_roles($username);

    for my $has_role (@$roles) {
        return 1 if $has_role eq $want_role;
    }

    return 0;
}

sub user_password {
    my ( $plugin, %params ) = @_;

    my ( $username, $realm );

    my @realms_to_check =
      $params{realm}
      ? ( $params{realm} )
      : ( keys %{ $plugin->realms } );

    # Expect either a code, username or nothing (for logged-in user)
    if ( exists $params{code} ) {
        my $code = $params{code} or return;
        foreach my $realm_check (@realms_to_check) {
            my $provider = $plugin->auth_provider($realm_check);

            # Realm may not support get_user_by_code
            my $username = try {
                $provider->get_user_by_code($code);
            }
            catch {
                $plugin->app->log( 'debug',
                    "Failed to check for code with $realm_check: $_" );
            };
            if ($username) {
                $realm = $realm_check;
                last;
            }
            else {
                $plugin->app->log( 'debug',
                    "No user found in realm $realm_check with code $code" );
            }
        }
        return unless $username;
    }
    else {
        if ( !$params{username} ) {
            $username = $plugin->app->session->read('logged_in_user')
              or die "No username specified and no logged-in user";
            $realm = $plugin->app->session->read('logged_in_user_realm');
        }
        else {
            $username = $params{username};
            $realm    = $params{realm};
        }
        if ( exists $params{password} ) {
            my $success;

            # Possible that realm will not be set before this statement
            ( $success, $realm ) =
              $plugin->authenticate_user( $username, $params{password},
                $realm );
            $success or return;
        }
    }

    # We now have a valid user. Reset the password?
    if ( my $new_password = $params{new_password} ) {
        if ( !$realm ) {

            # It's possible that the realm is unknown at this stage
            foreach my $realm_check (@realms_to_check) {
                my $provider = $plugin->auth_provider($realm_check);
                $realm = $realm_check if $provider->get_user_details($username);
            }
            return unless $realm;    # Invalid user
        }
        my $provider = $plugin->auth_provider($realm);
        $provider->set_user_password( $username, $new_password );
        if ( $params{code} ) {

            # Stop reset code being reused
            $provider->set_user_details( $username, pw_reset_code => undef );

            # Force them to login if this was a reset with a code. This forces
            # a check that they have the new password correct, and there is a
            # chance they could have been logged-in as another user
            $plugin->app->destroy_session;
        }
    }
    $username;
}

sub user_roles {
    my ( $plugin, $username, $realm ) = @_;
    my $session = $plugin->app->session;

    $username = $session->read('logged_in_user') unless defined $username;

    my $search_realm = ( $realm ? $realm : '' );

    my $roles =
      $plugin->auth_provider($search_realm)->get_user_roles($username);
    return unless defined $roles;
    return wantarray ? @$roles : $roles;
}

#
# private methods
#

sub _build_wrapper {
    my $plugin       = shift;
    my $require_role = shift;
    my $coderef      = shift;
    my $mode         = shift;

    my @role_list =
      ref $require_role eq 'ARRAY'
      ? @$require_role
      : $require_role;

    return sub {
        my $user = $plugin->logged_in_user;
        if ( !$user ) {
            $plugin->execute_plugin_hook( 'login_required', $coderef );

            # TODO: see if any code executed by that hook set up a response
            return $plugin->app->redirect(
                $plugin->app->request->uri_for(
                    $plugin->login_page,
                    { return_url => $plugin->app->request->request_uri }
                )
            );
        }

        my $role_match;

        # this is a private method and we should never need 'else'
        # uncoverable branch false count:3
        if ( $mode eq 'single' ) {
            for ( $plugin->user_roles ) {
                $role_match++ and last if _smart_match( $_, $require_role );
            }
        }
        elsif ( $mode eq 'any' ) {
            my %role_ok = map { $_ => 1 } @role_list;
            for ( $plugin->user_roles ) {
                $role_match++ and last if $role_ok{$_};
            }
        }
        elsif ( $mode eq 'all' ) {
            $role_match++;
            for my $role (@role_list) {
                if ( !$plugin->user_has_role($role) ) {
                    $role_match = 0;
                    last;
                }
            }
        }

        if ($role_match) {

            # We're happy with their roles, so go head and execute the route
            # handler coderef.
            return $coderef->($plugin);
        }

        $plugin->execute_plugin_hook( 'permission_denied', $coderef );

        # TODO: see if any code executed by that hook set up a response
        return $plugin->app->redirect(
            $plugin->app->request->uri_for(
                $plugin->denied_page,
                { return_url => $plugin->app->request->request_uri }
            )
        );
    };
}

sub _default_email_password_reset {
    my ( $plugin, %options ) = @_;

    my %message;
    if ( my $password_reset_text = $plugin->password_reset_text ) {
        no strict 'refs';
        %message = &{$password_reset_text}( $plugin, %options );
    }
    else {
        my $site = $plugin->app->request->uri_base;
        my $appname = $plugin->app->config->{appname} || '[unknown]';
        $message{subject} = "Password reset request";
        $message{from}    = $plugin->mail_from;
        $message{plain}   = <<__EMAIL;
A request has been received to reset your password for $appname. If
you would like to do so, please follow the link below:

$site/login/$options{code}
__EMAIL
    }

    $plugin->_send_email( to => $options{email}, %message );
}

sub _default_login_page {
    my $plugin    = shift;
    my $app       = $plugin->app;
    my $loginpage = $plugin->login_page;

    if ( my $new_password = $app->request->param('new_password') ) {
        return <<NEWPW;
<h1>New password</h1>
<p>
Your new password is $new_password
</p>
<a href="$loginpage">Click here to login</a>
NEWPW
    }

    if ( $app->request->param('reset_sent') ) {
        return <<SENT;
<h1>Request sent</h1>
<p>A password reset request has been sent. Please check your email.</p>
SENT
    }

    # Valid password reset request. Just need to confirm to
    # prevent GET requests by email filters
    if ( $app->request->param('password_code_valid') ) {
        return <<VALID;
<h1>Reset your password</h1>
<p>
Please click the button below to reset your password
</p>
<form method="post">
<input type="submit" name="confirm_reset" value="Reset password">
</form>
VALID
    }

    my $pwreset_html =
      !$plugin->reset_password_handler
      ? ""
      : <<RESETPW;
<h2>Password reset</h2>
<p>Enter your username to obtain an email to reset your password</p>
<label for="username_reset">Username:</label>
<input type="text" name="username_reset" id="username_reset">
<input type="submit" name="submit_reset" value="Submit">
RESETPW
    my $return_url = $app->request->params->{return_url} || '';

    my $login_fail_message =
      $app->request->vars->{login_failed}
      ? "<p>LOGIN FAILED</p>"
      : "";

    return <<PAGE;
<h1>Login Required</h1>

<p>
You need to log in to continue.
</p>

$login_fail_message

<form method="post">
<label for="username">Username:</label>
<input type="text" name="username" id="username">
<br />
<label for="password">Password:</label>
<input type="password" name="password" id="password">
<br />
<input type="hidden" name="return_url" value="$return_url">
<input type="submit" value="Login">
$pwreset_html
</form>
PAGE
}

sub _default_permission_denied_page {
    my $plugin = shift;
    return <<PAGE
<h1>Permission Denied</h1>

<p>
Sorry, you're not allowed to access that page.
</p>
PAGE
}

sub _default_welcome_send {
    my ( $plugin, %options ) = @_;

    my %message;
    if ( my $welcome_text = $plugin->welcome_text ) {
        no strict 'refs';
        %message = &{$welcome_text}( $plugin, %options );
    }
    else {
        my $site       = $plugin->app->request->base;
        my $host       = $site->host;
        my $appname    = $plugin->app->config->{appname} || '[unknown]';
        my $reset_link = $site . "login/$options{code}";
        $message{subject} = "Welcome to $host";
        $message{from}    = $plugin->mail_from;
        $message{plain}   = <<__EMAIL;
An account has been created for you at $host. If you would like
to accept this, please follow the link below to set a password:

$reset_link
__EMAIL
    }

    $plugin->_send_email( to => $options{email}, %message );
}

sub _email_mail_message {
    my ( $plugin, %params ) = @_;

    my $mailer_options = $plugin->mailer->{options} || {};

    my @parts;

    push @parts,
      Mail::Message::Body::String->new(
        mime_type   => 'text/plain',
        disposition => 'inline',
        data        => $params{plain},
      ) if ( $params{plain} );

    push @parts,
      Mail::Message::Body::String->new(
        mime_type   => 'text/html',
        disposition => 'inline',
        data        => $params{html},
      ) if ( $params{html} );

    @parts or die "No plain or HTML email text supplied";

    my $content_type = @parts > 1 ? 'multipart/alternative' : $parts[0]->type;

    Mail::Message->build(
        To             => $params{to},
        Subject        => $params{subject},
        From           => $params{from},
        'Content-Type' => $content_type,
        attach         => \@parts,
    )->send(%$mailer_options);
}

sub _send_email {
    my $plugin = shift;

    my $mailer = $plugin->mailer or die "No mailer configured";

    my $module = $mailer->{module}
      or die "No email module specified for mailer";

    if ( $module eq 'Mail::Message' ) {

        # require Mail::Message;
        require Mail::Message::Body::String;
        return $plugin->_email_mail_message(@_);
    }
    else {
        die "No support for $module. Please submit a PR!";
    }
}

# Given a class method name and a set of parameters, try calling that class
# method for each realm in turn, arranging for each to receive the configuration
# defined for that realm, until one returns a non-undef, then return the realm
# which succeeded and the response.
# Note: all provider class methods return a single value; if any need to return
# a list in future, this will need changing)
#
# FIXME: this is not used anywhere - what is it for?
sub _try_realms {
    my ( $plugin, $method, @args );
    for my $realm ( keys %{ $plugin->realms } ) {
        my $provider = $plugin->auth_provider($realm);
        if ( !$provider->can($method) ) {
            die "Provider $provider does not provide a $method method!";
        }
        if ( defined( my $result = $provider->$method(@args) ) ) {
            return $result;
        }
    }
    return;
}

#
# routes
#

# implementation of logout route
sub _logout_route {
    my $app = shift;
    my $req = $app->request;
    my $plugin = $app->with_plugin('Auth::Extensible');

    $app->destroy_session;

    if ( $req->params->{return_url} ) {
        $app->redirect( $req->params->{return_url} );
    }
    elsif ($plugin->exit_page) {
        $app->redirect($plugin->exit_page);
    }
    else {
        # TODO: perhaps make this more configurable, perhaps by attempting to
        # render a template first.
        return "OK, logged out successfully.";
    }
}

# implementation of post login route
sub _post_login_route {
    my $app = shift;
    my $plugin = $app->with_plugin('Auth::Extensible');

    # First check for password reset request, if applicable
    if (   $plugin->reset_password_handler
        && $app->request->param('submit_reset') )
    {
        my $username = $app->request->param('username_reset');
        die "Attempt to pass reference to reset blocked" if ref $username;
        $app->password_reset_send( username => $username );
        $app->forward(
            $plugin->login_page,
            { reset_sent => 1 },
            { method     => 'GET' }
        );
    }

    # Then for a password reset itself (confirmed by POST request)
    my ($code) =
         $plugin->reset_password_handler
      && $app->request->param('confirm_reset')
      && $app->request->splat;

    if ($code) {
        no strict 'refs';
        my $randompw = &{ $plugin->password_generator };
        if ( $app->user_password( code => $code, new_password => $randompw ) ) {
            $app->forward(
                $plugin->login_page,
                { new_password => $randompw },
                { method       => 'GET' }
            );
        }
    }

    # For security, ensure the username and password are straight scalars; if
    # the app is using a serializer and we were sent a blob of JSON, they could
    # have come from that JSON, and thus could be hashrefs (JSON SQL injection)
    # - for database providers, feeding a carefully crafted hashref to the SQL
    # builder could result in different SQL to what we'd expect.
    # For instance, if we pass password => params->{password} to an SQL builder,
    # we'd expect the query to include e.g. "WHERE password = '...'" (likely
    # with paremeterisation) - but if params->{password} was something
    # different, e.g. { 'like' => '%' }, we might end up with some SQL like
    # WHERE password LIKE '%' instead - which would not be a Good Thing.
    my ( $username, $password ) =
      @{ $app->request->params() }{qw(username password)};

    for ( $username, $password ) {
        if ( ref $_ ) {

            # TODO: handle more cleanly
            die "Attempt to pass a reference as username/password blocked";
        }
    }

    if ( $plugin->logged_in_user ) {
        $app->redirect( $app->request->params->{return_url}
              || $plugin->user_home_page );
    }

    my $auth_realm = $app->request->param('realm');
    my ( $success, $realm ) =
      $plugin->authenticate_user( $username, $password, $auth_realm );

    if ($success) {
        $app->app->session->write( logged_in_user       => $username );
        $app->app->session->write( logged_in_user_realm => $realm );
        $app->log( core => "Realm is $realm" );
        $app->redirect( $app->request->params->{return_url}
              || $plugin->user_home_page );
    }
    else {
        $app->request->vars->{login_failed}++;
        $app->forward(
            $plugin->login_page,
            { login_failed => 1 },
            { method       => 'GET' }
        );
    }
}

#
# private functions
#

sub _default_password_generator {
    Session::Token->new( length => 8 )->get;
}

sub _reset_code {
    Session::Token->new( length => 32 )->get;
}

# Replacement for much maligned and misunderstood smartmatch operator
sub _smart_match {
    my ( $got, $want ) = @_;
    if ( !ref $want ) {
        return $got eq $want;
    }
    elsif ( ref $want eq 'Regexp' ) {
        return $got =~ $want;
    }
    elsif ( ref $want eq 'ARRAY' ) {
        return grep { $_ eq $got } @$want;
    }
    else {
        carp "Don't know how to match against a " . ref $want;
    }
}

=head1 NAME

Dancer2::Plugin::Auth::Extensible - extensible authentication framework for Dancer2 apps

=head1 DESCRIPTION

A user authentication and authorisation framework plugin for Dancer2 apps.

Makes it easy to require a user to be logged in to access certain routes,
provides role-based access control, and supports various authentication
methods/sources (config file, database, Unix system users, etc).

Designed to support multiple authentication realms and to be as extensible as
possible, and to make secure password handling easy.  The base class for auth
providers makes handling C<RFC2307>-style hashed passwords really simple, so you
have no excuse for storing plain-text passwords.  A simple script called
B<generate-crypted-password> to generate
RFC2307-style hashed passwords is included, or you can use L<Crypt::SaltedHash>
yourself to do so, or use the C<slappasswd> utility if you have it installed.

=head1 SYNOPSIS

Configure the plugin to use the authentication provider class you wish to use:

  plugins:
        Auth::Extensible:
            realms:
                users:
                    provider: Example
                    ....

The configuration you provide will depend on the authentication provider module
in use.  For a simple example, see
L<Dancer2::Plugin::Auth::Extensible::Provider::Config>.

Define that a user must be logged in and have the proper permissions to 
access a route:

    get '/secret' => require_role Confidant => sub { tell_secrets(); };

Define that a user must be logged in to access a route - and find out who is
logged in with the C<logged_in_user> keyword:

    get '/users' => require_login sub {
        my $user = logged_in_user;
        return "Hi there, $user->{username}";
    };

=head1 AUTHENTICATION PROVIDERS

For flexibility, this authentication framework uses simple authentication
provider classes, which implement a simple interface and do whatever is required
to authenticate a user against the chosen source of authentication.

For an example of how simple provider classes are, so you can build your own if
required or just try out this authentication framework plugin easily, 
see L<Dancer2::Plugin::Auth::Extensible::Provider::Example>.

This framework supplies the following providers out-of-the-box:

=over 4

=item L<Dancer2::Plugin::Auth::Extensible::Provider::Unix>

Authenticates users using system accounts on Linux/Unix type boxes

=item L<Dancer2::Plugin::Auth::Extensible::Provider::Database>

Authenticates users stored in a database table

=item L<Dancer2::Plugin::Auth::Extensible::Provider::Config>

Authenticates users stored in the app's config

=back

The following external providers are also available on the CPAN:

=over 4

=item L<Dancer2::Plugin::Auth::Extensible::Provider::DBIC>

Authenticates users stored in a database table using L<Dancer2::Plugin::DBIC>

=back

Need to write your own?  Just create a new provider class which consumes
L<Dancer2::Plugin::Auth::Extensible::Role::Provider> and implements the
required methods, and you're good to go!

=head1 CONTROLLING ACCESS TO ROUTES

Keywords are provided to check if a user is logged in / has appropriate roles.

=over

=item require_login - require the user to be logged in

    get '/dashboard' => require_login sub { .... };

If the user is not logged in, they will be redirected to the login page URL to
log in.  The default URL is C</login> - this may be changed with the
C<login_page> option.

=item require_role - require the user to have a specified role

    get '/beer' => require_role BeerDrinker => sub { ... };

Requires that the user be logged in as a user who has the specified role.  If
the user is not logged in, they will be redirected to the login page URL.  If
they are logged in, but do not have the required role, they will be redirected
to the access denied URL.

=item require_any_roles - require the user to have one of a list of roles

    get '/drink' => require_any_role [qw(BeerDrinker VodaDrinker)] => sub {
        ...
    };

Requires that the user be logged in as a user who has any one (or more) of the
roles listed.  If the user is not logged in, they will be redirected to the
login page URL.  If they are logged in, but do not have any of the specified
roles, they will be redirected to the access denied URL.

=item require_all_roles - require the user to have all roles listed

    get '/foo' => require_all_roles [qw(Foo Bar)] => sub { ... };

Requires that the user be logged in as a user who has all of the roles listed.
If the user is not logged in, they will be redirected to the login page URL.  If
they are logged in but do not have all of the specified roles, they will be
redirected to the access denied URL.

=back

=head2 Replacing the Default C< /login > and C< /login/denied > Routes

By default, the plugin adds a route to present a simple login form at that URL.
If you would rather add your own, set the C<no_default_pages> setting to a true
value, and define your own route which responds to C</login> with a login page.
Alternatively you can let DPAE add the routes and handle the status codes, etc.
and simply define the setting C<login_page_handler> and/or
C<permission_denied_page_handler> with the name of a subroutine to be called to
handle the route. Note that it must be a fully qualified sub. E.g.

    plugins:
      Auth::Extensible:
        login_page_handler: 'My::App::login_page_handler'
        permission_denied_page_handler: 'My::App::permission_denied_page_handler'

Then in your code you might simply use a template:

    sub permission_denied_page_handler {
        template 'account/login';
    }

If the user is logged in, but tries to access a route which requires a specific
role they don't have, they will be redirected to the "permission denied" page
URL, which defaults to C</login/denied> but may be changed using the
C<denied_page> option.

Again, by default a route is added to respond to that URL with a default page;
again, you can disable this by setting C<no_default_pages> and creating your
own.

This would still leave the routes C<post '/login'> and C<any '/logout'>
routes in place. To disable them too, set the option C<no_login_handler> 
to a true value. In this case, these routes should be defined by the user,
and should do at least the following:

    post '/login' => sub {
        my ($success, $realm) = authenticate_user(
            params->{username}, params->{password}
        );
        if ($success) {
            session logged_in_user => params->{username};
            session logged_in_user_realm => $realm;
            # other code here
        } else {
            # authentication failed
        }
    };
    
    any '/logout' => sub {
        app->destroy_session;
    };

If you want to use the default C<post '/login'> and C<any '/logout'> routes
you can configure them. See below.

The default routes also contain functionality for a user to perform password
resets. See the L<PASSWORD RESETS> documentation for more details.

=head2 Keywords

=over

=item require_login

Used to wrap a route which requires a user to be logged in order to access
it.

    get '/secret' => require_login sub { .... };

=item require_role

Used to wrap a route which requires a user to be logged in as a user with the
specified role in order to access it.

    get '/beer' => require_role BeerDrinker => sub { ... };

You can also provide a regular expression, if you need to match the role using a
regex - for example:

    get '/beer' => require_role qr/Drinker$/ => sub { ... };

=item require_any_role

Used to wrap a route which requires a user to be logged in as a user with any
one (or more) of the specified roles in order to access it.

    get '/foo' => require_any_role [qw(Foo Bar)] => sub { ... };

=item require_all_roles

Used to wrap a route which requires a user to be logged in as a user with all
of the roles listed in order to access it.

    get '/foo' => require_all_roles [qw(Foo Bar)] => sub { ... };


=item logged_in_user

Returns a hashref of details of the currently logged-in user, if there is one.

The details you get back will depend upon the authentication provider in use.

=item get_user_details

Returns a hashref of details of the specified user. The realm can optionally
be specified as the second parameter. If the realm is not specified, each
realm will be checked, and the first matching user will be returned.

The details you get back will depend upon the authentication provider in use.

=item user_has_role

Check if a user has the role named.

By default, the currently-logged-in user will be checked, so you need only name
the role you're looking for:

    if (user_has_role('BeerDrinker')) { pour_beer(); }

You can also provide the username to check; 

    if (user_has_role($user, $role)) { .... }

=item user_roles

Returns a list of the roles of a user.

By default, roles for the currently-logged-in user will be checked;
alternatively, you may supply a username to check.

Returns a list or arrayref depending on context.

=item authenticate_user

Usually you'll want to let the built-in login handling code deal with
authenticating users, but in case you need to do it yourself, this keyword
accepts a username and password, and optionally a specific realm, and checks
whether the username and password are valid.

For example:

    if (authenticate_user($username, $password)) {
        ...
    }

If you are using multiple authentication realms, by default each realm will be
consulted in turn.  If you only wish to check one of them (for instance, you're
authenticating an admin user, and there's only one realm which applies to them),
you can supply the realm as an optional third parameter.

In boolean context, returns simply true or false; in list context, returns
C<($success, $realm)>.

=item logged_in_user_lastlogin

Returns (as a DateTime object) the time of the last successful login of the
current logged in user.

To enable this functionality, set the configuration key C<record_lastlogin> to
a true value. The backend provider must support write access for a user and
have lastlogin functionality implemented.

=item update_user

Updates a user's details. If the authentication provider supports it, this
keyword allows a user's details to be updated within the backend data store.

In order to update the user's details, the keyword should be called with the
username to be updated, followed by a hash of the values to be updated. Note
that whilst the password can be updated using this method, any new value will
be stored directly into the provider as-is, not encrypted. It is recommended to
use L</user_password> instead.

If only one realm is configured then this will be used to search for the user.
Otherwise, the realm must be specified with the realm key.

    # Update user, only one realm configured
    update_user "jsmith", surname => "Smith"

    # Update a user's username, more than one realm
    update_user "jsmith", realm => "dbic", username => "jjones"

The updated user's details are returned, as per L<logged_in_user>.

=item update_current_user

The same as L<update_user>, but does not take a username as the first parameter,
instead updating the currently logged-in user.

    # Update user, only one realm configured
    update_current_user surname => "Smith"

The updated user's details are returned, as per L<logged_in_user>.

=item create_user

Creates a new user, if the authentication provider supports it. Optionally
sends a welcome message with a password reset request, in which case an
email key must be provided.

This function works in the same manner as L<update_user>, except that
the username key is mandatory. As with L<update_user>, it is recommended
not to set a password directly using this method, otherwise it will be
stored in plain text.

The realm to use must be specified with the key C<realm> if there is more
than one realm configured.

    # Create new user
    create_user username => "jsmith", realm => "dbic", surname => "Smith"

    # Create new user and send welcome email
    create_user username => "jsmith", email => "john@you.com", email_welcome => 1

On success, the created user's details are returned, as per L<logged_in_user>.

The text sent in the welcome email can be customised in 2 ways, in the same way
as L<password_reset_send>:

=over

=item welcome_send

This can be used to specify a subroutine that will be called to perform the
entire message construction and email sending. Note that it must be a
fully-qualified sub such as C<My::App:email_welcome_send>. The subroutine will
be passed the dsl as the first parameter, followed by a hash with the keys
C<code>, C<email> and C<user>, which contain the generated reset code, user
email address, and user hashref respectively.  For example:

    sub reset_send_handler {
        my ($dsl, %params) = @_;
        my $user_email = $params{email};
        my $reset_code = $params{code};
        # Send email
        return $result;
    }

=item welcome_text

This can be used to generate the text for the welcome email, with this module
sending the actual email itself. It must be a fully-qualified sub, as per the
previous option. It will be passed the same parameters as
L<welcome_send>, and should return a hash with the same keys as
L<password_reset_send_email>.

=back

=item password_reset_send

L</password_reset_send> sends a user an email with a password reset link. Along
with L</user_password>, it allows a user to reset their password.

The function must be called with the key C<username> and a value that is the
username. The username specified will be sent an email with a link to reset
their password. Note that the provider being used must return the email address
in the key C<email>, which in the case of a database will normally require that
column to exist in the user's table. The provider must be able to write values
to the user in order for this function to store the generated code.

If the username is not found, a value of 0 is returned. If the username is
found and the email is sent successfully, 1 is returned. Otherwise undef is
returned.  Note: if you are displaying a success message, and you do not want
people to be able to check the existance of a user on your system, then you
should check for the return value being defined, not true. For example:

    say "Success" if defined password_reset_send username => username;

Note that this still leaves the possibility of checking the existance of a user
if the email send mechanism is failing.

The realm can also be specified using the key realm:

    password_reset_send username => 'jsmith', realm => 'dbic'

Default text for the email is automatically produced and emailed. This can be
customized with one of 2 config parameters:

=over

=item password_reset_send_email

This can be used to specify a subroutine that will be called to perform the
entire message construction and email sending. Note that it must be a
fully-qualified sub such as C<My::App:reset_send_handler>. The subroutine will
be passed the dsl as the first parameter, followed by a hash with the keys
C<code> and C<email>, which contain the generated reset code and user email
address respectively.  For example:

    sub reset_send_handler {
        my ($dsl, %params) = @_;
        my $user_email = $params{email};
        my $reset_code = $params{code};
        # Send email
        return $result;
    }

=item password_reset_text

This can be used to generate the text for the email, with this module sending
the actual email itself. It must be a fully-qualified sub, as per the previous
option. It will be passed the same parameters as L<password_reset_send_email>,
and should return a hash with the following keys:

=over

=item subject

The subject of the email message.

=item from

The sender of the email message (optional, can also be specified using
C<mail_from>.

=item plain

Plain text for the email. Either this, or html, or both should be returned.

=item html

HTML text for the email (optional, as per plain).

=back

Here is an example subroutine:

    sub reset_text_handler {
        my ($dsl, %params) = @_;
        return (
            from    => '"My name" <myapp@example.com',
            subject => 'the subject',
            plain   => "reset here: $params{code}",
        );
    }

# Example configuration

    Auth::Extensible:
        mailer:
            module: Mail::Message # Module to send email with
            options:              # Module options
                via: sendmail
        mail_from: '"My app" <myapp@example.com>'
        password_reset_text: MyApp::reset_send

=back

=item user_password

This provides various functions to check or reset a user's password, either
from a reset code that was previously send by L<password_reset_send> or
directly by specifying a username and password. Functions that update a
password rely on a provider that has write access to a user's details.

By default, the user to update is the currently logged-in user. A specific user
can be specified with the key C<username> for a certain username, or C<code>
for a previously sent reset code. Using these parameters on their own will
return the username if it is a valid request.

If the above parameters are specified with the additional parameter
C<new_password>, then the password will be set to that value, assuming that it
is a valid request.

The realm can be optionally specified with the keyword C<realm>.

Examples:

Check the logged-in user's password:

    user_password password => 'mysecret'

Check a specific user's password:

    user_password username => 'jsmith', password => 'bigsecret'

Check a previously sent reset code:

    user_password code => 'XXXX'

Reset a password with a previously sent code:

    user_password code => 'XXXX', new_password => 'newsecret'

Change a user's password (username optional)

    user_password username => 'jbloggs', password => 'old', new_password => 'secret'

Force set a specific user's password, without checking existing password:

    user_password username => 'jbloggs', new_password => 'secret'

=item logged_in_user_password_expired

Returns true if the password of the currently logged in user has expired.  To
use this functionality, the provider must support the C<password_expired>
function, and must be configured accordingly. See the relevant provider for
full configuration details.

Note that this functionality does B<not> prevent the user accessing any
protected pages, even if the password has expired. This is so that the
developer can still leave some protected routes available, such as a page to
change the password. Therefore, if using this functionality, it is suggested
that a check is done in the C<before> hook:

    hook before => sub {
        if (logged_in_user_password_expired)
        {
            # Redirect to user details page if password expired, but only if that
            # is not the currently request page to prevent redirect loops
            redirect '/password_update' unless request->uri eq '/password_update';
        }
    }

=back

=head2 PASSWORD RESETS

A variety of functionality is provided to make it easier to manage requests
from users to reset their passwords. The keywords L<password_reset_send> and
L<user_password> form the core of this functionality - see the documentation of
these keywords for full details. This functionality can only be used with a
provider that supports write access.

When utilising this functionality, it is wise to only allow passwords to be
reset with a POST request. This is because some email scanners "open" links
before delivering the email to the end user. With only a single-use GET
request, this will result in the link being "used" by the time it reaches the
end user, thus rendering it invalid.

Password reset functionality is also built-in to the default route handlers.
To enable this, set the configuration value C<reset_password_handler> to a true
value (having already configured the mail handler, as per the keyword
documentation above). Once this is done, the default login page will contain
additional form controls to allow the user to enter their username and request
a reset password link.

By default, the default handlers will generate a random 8 character password using
L<Session::Token>. To use your own function, set C<password_generator> in your
configuration. See the L<SAMPLE CONFIGURATION> for an example.

If using C<login_page_handler> to replace the default login page, you can still
use the default password reset handlers. Add 2 controls to your form for
submitting a password reset request: a text input called username_reset for the
username, and submit_reset to submit the request. Your login_page_handler is
then passed the following additional params:

=over

=item new_password

Contains the new automatically-generated password, once the password reset has
been performed successfully.

=item reset_sent

Is true when a password reset has been emailed to the user.

=item password_code_valid

Is true when a valid password reset code has been submitted with a GET request.
In this case, the user should be given the chance to confirm with a POST
request, with a form control called C<confirm_reset>.

For a full example, see the default handler in this module's code.

=back

=head2 SAMPLE CONFIGURATION

In your application's configuation file:

    session: simple
    plugins:
        Auth::Extensible:
            # Set to 1 if you want to disable the use of roles (0 is default)
            disable_roles: 0
            # After /login: If no return_url is given: land here ('/' is default)
            user_home_page: '/user'
            # After /logout: If no return_url is given: land here (no default)
            exit_page: '/'

            # Mailer options for reset password and welcome emails
            mailer:
                module: Mail::Message # Email module to use
                options:              # Options for module
                    via: sendmail     # Options passed to $msg->send
            mail_from: '"App name" <myapp@example.com>' # From email address

            # Set to true to enable password reset code in the default handlers
            reset_password_handler: 1
            password_generator: My::App::random_pw # Optional random password generator

            # Set to a true value to enable recording of successful last login times
            record_lastlogin: 1

            # Password reset functionality
            password_reset_send_email: My::App::reset_send # Customise sending sub
            password_reset_text: My::App::reset_text # Customise reset text

            # create_user options
            welcome_send: My::App::welcome_send # Customise welcome email sub
            welcome_text: My::App::welcome_text # Customise welcome email text

            # List each authentication realm, with the provider to use and the
            # provider-specific settings (see the documentation for the provider
            # you wish to use)
            realms:
                realm_one:
                    provider: Database
                        db_connection_name: 'foo'

B<Please note> that you B<must> have a session provider configured.  The 
authentication framework requires sessions in order to track information about 
the currently logged in user.
Please see L<Dancer2::Core::Session> for information on how to configure session 
management within your application.

=head1 FUNCTIONS

=head2 auth_provider($dsl, $realm)

Given a realm, returns a configured and ready to use instance of the provider
specified by that realm's config.

=head1 AUTHOR

David Precious, C<< <davidp at preshweb.co.uk> >>

Dancer2 port of Dancer::Plugin::Auth::Extensible by:

Stefan Hornburg (Racke), C<< <racke at linuxia.de> >>

Conversion to Dancer2's new plugin system in 2016 by:

Peter Mottram (SysPete), C<< <peter at sysnix.com> >>

=head1 BUGS / FEATURE REQUESTS

This is an early version; there may still be bugs present or features missing.

This is developed on GitHub - please feel free to raise issues or pull requests
against the repo at:
L<https://github.com/PerlDancer/Dancer2-Plugin-Auth-Extensible>

=head1 ACKNOWLEDGEMENTS

Valuable feedback on the early design of this module came from many people,
including Matt S Trout (mst), David Golden (xdg), Damien Krotkine (dams),
Daniel Perrett, and others.

Configurable login/logout URLs added by Rene (hertell)

Regex support for require_role by chenryn

Support for user_roles looking in other realms by Colin Ewen (casao)

LDAP provider added by Mark Meyer (ofosos)

Documentation fix by Vince Willems.

Henk van Oers (GH #8, #13).

Andrew Beverly (GH #6, #7, #10, #17, #22, #24, #25, #26).
This includes support for creating and editing users and manage user passwords.

Gabor Szabo (GH #11, #16, #18).

Evan Brown (GH #20, #32).

Jason Lewis (Unix provider problem).

=head1 LICENSE AND COPYRIGHT

Copyright 2012-16 David Precious.

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

See http://dev.perl.org/licenses/ for more information.

=cut

1;    # End of Dancer2::Plugin::Auth::Extensible
