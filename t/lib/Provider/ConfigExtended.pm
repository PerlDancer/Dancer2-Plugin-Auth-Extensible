package Provider::ConfigExtended;

use Carp qw(croak);
use DateTime;
use List::Util qw(first);
use Moo;
extends "Dancer2::Plugin::Auth::Extensible::Provider::Config";
use namespace::clean;

sub create_user {
    my ( $self, %user ) = @_;

    my $username = delete $user{username};
    croak "User already exists"
      if first { $_->{user} eq $username } @{ $self->users };

    push @{ $self->users }, { user => $username };

    $self->set_user_details( $username, %user );
}

sub get_user_by_code {
    my ( $self, $code ) = @_;
    my $user = first { $_->{pw_reset_code} eq $code } @{ $self->users };
    return unless $user;
    return $user->{user};
}

sub set_user_details {
    my ( $self, $username, %update ) = @_;
    my $user = first { $_->{user} eq $username } @{ $self->users };
    return unless $user;
    foreach my $key ( keys %update ) {
        $user->{$key} = $update{$key};
    }
    return $self->get_user_details( $user->{user} );
}

sub set_user_password {
    my ( $self, $username, $password ) = @_;
    my $encrypted = $self->encrypt_password($password);
    $self->set_user_details( $username, pass => $encrypted );
}

sub password_expired {
    my ( $self, $user ) = @_;
    my $expiry = $self->password_expiry_days or return 0;
    my $last_changed = $user->{pwchanged};
    return 1 unless $last_changed;

    my $duration = $last_changed->delta_days( DateTime->now );
    $duration->in_units('days') > $expiry ? 1 : 0;
}

1;
