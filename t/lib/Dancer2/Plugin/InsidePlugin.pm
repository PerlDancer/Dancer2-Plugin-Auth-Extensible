package Dancer2::Plugin::InsidePlugin;

use strict;
use warnings;

use Dancer2::Plugin2;
use Dancer2::Plugin::Auth::Extensible ();

has auth_extensible => (
    is => 'ro',
    lazy => 1,
    default => sub {
        scalar $_[0]->app->with_plugins( 'Auth::Extensible' )
    },
    handles => [ 'require_login' ],
);

sub members_route {
    return 'Welcome member';
}

sub BUILD {
    my $plugin = shift;

    $plugin->app->add_route(
        method => 'get',
        regexp => '/members',
        code   => $plugin->require_login(\&members_route),
    )
}

1;
