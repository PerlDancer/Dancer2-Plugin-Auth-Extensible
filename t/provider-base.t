use strict;
use warnings;

use Test::More;
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

throws_ok { $provider->authenticate_user } qr/not implemented/,
  "authenticate_user not implemented";

throws_ok { $provider->get_user_details } qr/not implemented/,
  "get_user_details not implemented";

throws_ok { $provider->set_user_details } qr/not implemented/,
  "set_user_details not implemented";

throws_ok { $provider->get_user_roles } qr/not implemented/,
  "get_user_roles not implemented";

throws_ok { $provider->set_user_password } qr/not implemented/,
  "set_user_password not implemented";

throws_ok { $provider->password_expired } qr/not implemented/,
  "password_expired not implemented";

done_testing;
