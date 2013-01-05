package VKontakte::API::Standalone;

use 5.008000;
use strict;
use warnings;

use URI;
use WWW::Mechanize;
use JSON;
use Carp;

our $VERSION = '0.1';

sub new {
	my ($class,$id) = @_;
	my $self = bless {},$class;
	$self->{api_id} = $id;
	$self->{browser} =  WWW::Mechanize::->new(
		agent => __PACKAGE__.$VERSION,
		autocheck => 1,
	);
	return $self;
}

sub _request {
	my ($self, $params, $base) = @_;
	(my $uri = URI::->new($base))->query_form($params);
	return $self->{browser}->get($uri);
}

sub auth {
	my ($self,$login,$password,$scope) = @_;
	$self->_request(
		{
			client_id => $self->{api_id},
			redirect_uri => "blank.html",
			scope => $scope,
			response_type => "token",
			display => "wap",
		}, "https://api.vkontakte.ru/oauth/authorize"
	);
	$self->{browser}->submit_form(
		with_fields => {
			email => $login,
			pass => $password,
		},
	); # log in
	$self->{browser}->submit unless $self->{browser}->uri =~ m|^https://oauth.vk.com/blank.html|; # allow access if requested to
	my %params = map { split /=/,$_,2 } split /&/,$1 if $self->{browser}->uri =~ m|https://oauth.vk.com/blank.html#(.*)|;
	croak "No access_token returned (wrong login/password?)\n" unless defined $params{access_token};
	$self->{access_token} = $params{access_token};
	return $self;
}

sub api {
	my ($self,$method,$params) = @_;
	croak "Cannot make API calls unless authentificated" unless defined $self->{access_token};
	$params->{access_token} = $self->{access_token};
	return decode_json $self->_request($params,"https://api.vk.com/method/$method")->decoded_content;
}

1;
__END__

=head1 NAME

VKontakte::API::Standalone - Perl extension for creating standalone Vkontakte API applications

=head1 SYNOPSIS

  use VKontakte::API::Standalone;
  my $vk = new VKontakte::API::Standalone "12345678";
  $vk->auth("+1234567890","superpassword","wall,messages");
  $vk->api("activity.set",{text => "playing with VK API"});


=head1 DESCRIPTION

This module is just a wrapper for some JSON parsing and WWW::Mechanize magic, not much else.

=head1 CONSTRUCTOR METHODS

=over 4

=item $vk = VKontakte::API::Standalone::->new($api_id);

This creates the main object, sets the API ID variable (which can be got from the application
management page) and creates the WWW::Mechanize object.

=back 

=head1 ATTRIBUTES

=over

=item $vk->auth($login,$password,$scope)

This method should be called first. It uses OAuth2 to authentificate the user at the vk.com server
and accepts the specified scope (seen at https://vk.com/developers.php?oid=-17680044&p=Application_Access_Rights).
After obtaining the access token is saved for future use.

=item $vk->api($method,{parameter => "value", parameter => "value" ...})

This method calls the API methods on the server, as described on https://vk.com/developers.php?oid=-17680044&p=Making_Requests_to_API.
Resulting JSON is parsed and returned as a hash reference.

=back 

=head1 BUGS

Probably many. This is beta version.

API usage timeout is not handled.

Request frequency is not limited. Some of your requests will fail if you are
too fast.

=head1 SEE ALSO

https://vk.com/developers.php for the list of methods and how to use them.

=head1 AUTHOR

Krylov Ivan, E<lt>krylov.r00t@gmail.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2012 by Krylov Ivan

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
