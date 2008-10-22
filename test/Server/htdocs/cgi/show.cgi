#!/usr/bin/perl -w

use strict;
use CGI;

my $cgi = new CGI;
my $method = $ENV{"REQUEST_METHOD"};
my $user = $ENV{"REMOTE_USER"};
my $action = $cgi->param('action');
my $data = $cgi->param('access_log');


print "Content-type: text/plain\r\n";
print "\r\n";
print "$method: action=$action\n";
print "$data\n";
print "done\n";

