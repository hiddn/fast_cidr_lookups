#! /usr/bin/env perl

use strict;
use vars qw(%vars %obj %obj_override %exe);
use warnings;
use File::Basename qw(basename);
use File::Temp qw(tempfile);

%vars = (
	'CC' => 'cc',
	'CFLAGS' => '-Wall -Wextra -Werror',
	'CFLAGS_DBG' => '-g -ggdb -O0 -DCIDR_DEBUG_ENABLED',
	'CFLAGS_OPT' => '-O2',
	'LDFLAGS_DBG' => '$cflags_dbg',
	'LDFLAGS_OPT' => '$cflags_opt',
);

# Gather up build variables.
load_vars();

# Override particular files.
%obj_override = (
	'bench-cidr-lookups.o' => {
		IN => 'tests/bench-cidr.c',
		CFLAGS => '-DCIDR_LOOKUPS_API',
	},
	'bench-lpc-trie.o' => {
		IN => 'tests/bench-cidr.c',
		CFLAGS => '-DLPC_TRIE_API',
	},
);

# Generate rules for executables.
add_exe('cidr', '', 'src/cidr_lookups.c', 'src/irc_stuff.c', 'tests/tests.c');
add_exe('example', '', 'src/cidr_lookups.c', 'src/irc_stuff.c', 'example.c');
add_exe('bench-cidr-lookups', '-lm', 'src/cidr_lookups.c', 'src/irc_stuff.c', 'bench-cidr-lookups.o');

# Emit the output file.
my ($fh, $filename) = tempfile('build.ninja.XXXXXX');
gen_ninja($fh);
rename($filename, $ARGV[0] || 'build.ninja');

sub load_vars {
	# Environment can override the defaults.
	for my $key (keys %vars) {
		if (my $val = $ENV{$key}) {
			$vars{$key} = $val;
		}
	}

	# Command line can override the environment.
	for my $arg (@ARGV) {
		if ($arg =~ /^([^=]+)=(.*)$/) {
			$vars{$1} = $2 if exists $vars{$1};
		}
	}

	# Assign "derived" variables as needed.
	$vars{LD} ||= $vars{CC};
}

sub qualify_obj {
	my ($name, $dir) = @_;
	if ($name =~ m,^(?:src/|tests/|)([^/]+)\.c$,) {
		my $res = "$dir$1.o";
		$obj{$res} ||= { IN => $name };
		return $res;
	}
	if (exists $obj_override{$name}) {
		my $res = "$dir$name";
		$obj{$res} ||= $obj_override{$name};
		return $res;
	}
	die "wut $name $dir\n";
	return $name if $name =~ /\//;
	return $name = $dir . $name;
}

sub add_exe {
	my ($out, $libs, @objs) = @_;

	if ($out =~ /\//) {
		$exe{$out} = {OBJS => \@objs, LIBS => $libs};
	} else {
		add_exe('bin/opt/' . $out, $libs, (map qualify_obj($_, 'obj/opt/'), @objs));
		add_exe('bin/dbg/' . $out, $libs, (map qualify_obj($_, 'obj/dbg/'), @objs));
	}
}

sub gen_ninja_header {
	my ($fh) = @_;

	$fh->print(<<NINJA);
ninja_required_version = 1.5

cflags_dbg = $vars{CFLAGS} $vars{CFLAGS_DBG}
cflags_opt = $vars{CFLAGS} $vars{CFLAGS_OPT}
ldflags_dbg = $vars{LDFLAGS_DBG}
ldflags_opt = $vars{LDFLAGS_OPT}

rule cc_dbg
  deps = gcc
  depfile = \$out.d
  command = $vars{CC} \$cflags_dbg -o \$out -MD -MF \$depfile -c \$in

rule cc_opt
  deps = gcc
  depfile = \$out.d
  command = $vars{CC} \$cflags_opt -o \$out -MD -MF \$depfile -c \$in

rule ld_dbg
  command = $vars{LD} \$ldflags_dbg -o \$out \$in \$libs

rule ld_opt
  command = $vars{LD} \$ldflags_opt -o \$out \$in \$libs

rule configure
  generator = yes
  command = perl \$in \$out

build build.ninja: configure configure.pl
NINJA
}

sub gen_obj_builds {
	my ($fh) = @_;

	for my $name (sort keys %obj) {
		my $hash = $obj{$name};

		# What rule should we use?
		my $rule = $hash->{RULE};
		$rule ||= 'cc_dbg' if $name =~ m|^obj/dbg/|;
		$rule ||= 'cc_opt' if $name =~ m|^obj/opt/|;
		die "no rule found for object file $name\n" unless $rule;

		# What is our input file?
		my $in = $hash->{IN} || $name;
		do {
			$in = 'src/' . $in unless $in =~ m|/|;
			$in = $in . '.c' unless $in =~ m|\.|;
		} unless $in;

		# Should we add the object-file suffix?
		my $out = $hash->{OUT};
		do {
			$out = $name;
			$out .= '.o' unless $out =~ m|\.o$|;
		} unless $out;

		# Emit the "build" statement.
		$fh->print("\nbuild $out: $rule $in\n");
		$fh->print(" cflags_dbg=$hash->{CFLAGS} $vars{CFLAGS} $vars{CFLAGS_DBG}\n")
			if $hash->{CFLAGS} and $rule eq 'cc_dbg';
		$fh->print(" cflags_opt=$hash->{CFLAGS} $vars{CFLAGS} $vars{CFLAGS_OPT}\n")
			if $hash->{CFLAGS} and $rule eq 'cc_opt';
	}
}

sub gen_exe_builds {
	my ($fh) = @_;

	for my $name (sort keys %exe) {
		my $hash = $exe{$name};

		# What rule should we use?
		my $rule = $hash->{RULE};
		$rule ||= 'ld_dbg' if $name =~ m|^bin/dbg/|;
		$rule ||= 'ld_opt' if $name =~ m|^bin/opt/|;
		die "no rule found for executable $name\n" unless $rule;

		# What are our input object files?
		my $in = join(' ', @{$hash->{OBJS}});

		# What is our putput file name?
		my $out = $name;

		# Emit the "build" statement.
		$fh->print("\nbuild $out: $rule $in\n");
		$fh->print(" libs=$hash->{LIBS}\n") if $hash->{LIBS};
	}
}

sub gen_ninja {
	my ($fh) = @_;

	gen_ninja_header($fh);
	gen_exe_builds($fh);
	gen_obj_builds($fh);
}
