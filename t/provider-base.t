use strict;
use warnings;

use Test::More tests => 14 + 6;
use Test::Exception;
use Dancer2::Plugin::Auth::Extensible::Provider::Base;

my ( $provider, $password );

lives_ok {
    $provider =
      Dancer2::Plugin::Auth::Extensible::Provider::Base->new( 'realm_info',
        'dsl_thing' )
}
"Provider::Base->new";

is $provider->realm_settings, 'realm_info', "realm_settings method";
is $provider->realm_dsl,      'dsl_thing',  "realm_dsl method";

ok $provider->match_password( 'password', 'password' ), "good plain password";
ok $provider->match_password(
    'password', '{SSHA}ljxuwXYQH3BDNZjg+VXBrkw6Sh6sta3l'
  ),
  "good SHA password";

ok !$provider->match_password( 'bad', 'password' ), "bad plain password";
ok !$provider->match_password( 'bad',
    '{SSHA}ljxuwXYQH3BDNZjg+VXBrkw6Sh6sta3l' ), "bad SHA password";

lives_ok { $password = $provider->encrypt_password } "encrypt_password(undef)";
like $password, qr/^{SSHA}.+$/, "password looks good";

lives_ok { $password = $provider->encrypt_password('password') }
"encrypt_password('password')";
like $password, qr/^{SSHA}.+$/, "password looks good";

lives_ok { $password = $provider->encrypt_password( 'password', 'SHA-1' ) }
"encrypt_password('password', 'SHA-1')";
like $password, qr/^{SSHA}.+$/, "password looks good";

my @methods = (
    qw/ authenticate_user get_user_details set_user_details
      get_user_roles set_user_password password_expired /
);

can_ok( $provider, @methods );

foreach my $method (@methods) {
    throws_ok { $provider->$method } qr/$method.+not implemented/,
      "$method not implemented";
}
