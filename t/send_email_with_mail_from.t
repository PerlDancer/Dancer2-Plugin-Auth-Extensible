use warnings;
use strict;
use Test::More;
use Test::Deep qw(cmp_deeply ignore re superbagof);
use Test::Fatal;

BEGIN {
    $ENV{DANCER_CONFDIR}         = 't/lib';
    $ENV{DANCER_ENVIRONMENT}     = 'mail-from';
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

is $transport->delivery_count, 1, "... and we see 1 email sent";

my $delivery = $transport->shift_deliveries;
my $email    = $delivery->{email};

is $email->get_body, "the body", "... and we see the expected email body";
like $email->get_header('Content-Type'), qr{text/plain},
  "... and content type is text/plain";
like $email->get_header('Content-Type'), qr{charset="utf-8"},
  "... and charset is utf-8";

cmp_deeply $delivery->{envelope},
  { from => 'testing@example.com', to => ['james@example.com'] },
  "... and we see from address as per mail_from config attribute.";

done_testing;
