use warnings;
use strict;
use Test::More;
use Test::Deep qw(cmp_deeply ignore re superbagof);
use Test::Fatal;

BEGIN {
    $ENV{DANCER_CONFDIR}         = 't/lib';
    $ENV{DANCER_ENVIRONMENT}     = 'no-mail-from';
    $ENV{EMAIL_SENDER_TRANSPORT} = 'Test';
}

use Dancer2;
use Dancer2::Plugin::Auth::Extensible;

set logger => 'capture';
set log    => 'debug';

my $plugin = app->with_plugin("Auth::Extensible");

my $transport = Email::Sender::Simple->default_transport;
my $trap      = app->logger_engine->trapper;

is exception {
    $plugin->_send_email( plain => "the body" )
},
  undef,
  "Calling _send_email with plain text but no recipients lives";

is $transport->delivery_count, 0, "... but no emails sent";

my $logs = $trap->read;
cmp_deeply $logs,
  superbagof(
    {
        formatted => ignore(),
        level     => "error",
        message   => re(qr/Unable to send email: no recipients/)
    }
  ),
  "... and we have error logged regarding no recipients."
  or diag explain $logs;

is exception {
    $plugin->_send_email(
        plain => "the body",
        to    => 'james@example.com'
      )
}, undef, "Calling _send_email with plain text and recipient lives";

is $transport->delivery_count, 0, "... and we see 0 email sent";

done_testing;
