#!/usr/bin/perl -w
#具备多个变量的追踪功能。
$|=1;

sub validate_variable(@$){      #验证变量是否已在数组中，若在则返回1，不在则返回0
	@arr = shift;
	$va = shift;
	foreach $ar (@arr){
		if($ar eq $va){
			return 1;
		}else{
			next;
		}
	}
	return 0;
}

open(CONTENT, "c:\\edit.asp");
@content=<CONTENT>;
close(CONTENT);

@variable_database=0;
undef($variable);

#读某一个变量获得的行数--启始行
$variable_line=0;
$variable_line2=0;
NEWLINE: foreach $everyline (@content){
	$variable_line++;
	if(((lc($everyline)=~/(<*)(\%*)([ ]*)(.*)([ ]*)=([ ]*)request\.(.*)\(/)
	|| (lc($everyline)=~/(<*)(\%*)([ ]*)(.*)([ ]*)=([ ]*)request\(/))
	&& (&validate_variable(@variable_database,$4)==0)){
		$variable=$4;
		$variable_headline=$variable_line;
		push(@variable_database, $variable);
		print "BEGIN: $variable_headline : $variable\n";
		
		#读某一个变量构造成SQL语句后的行数--结束行
		foreach $everyline2 (@content){
			$variable_line2++;
			if(lc($everyline2)=~/\"[select|insert|update|delete](.*)&([ ]*)$variable([ ]|\n|&)/){
				$variable_lastline=$variable_line2;
				print "LAST: $variable_lastline : $variable\n";
				
				#读取启始行与结束行之间是否有replace或cint
				if(($variable_headline!=0) && ($variable_lastline!=0) && ($variable_lastline>=$variable_headline)){
					for($count=($variable_headline-1) ;$count<=($variable_lastline-1); $count++){
						if((lc($content[$count])=~/(.*)replace\($variable([ ]*),([ ]*)\"\'\"(.*)/)
		 				|| (lc($content[$count])=~/(.*)cint\(([ ]*)$variable/)){
		 					$variable_line2=0;
							next NEWLINE;
						}else{
							print "SQL Injection : $variable\n";
							$variable_line2=0;
							next NEWLINE;
						}
					}
				}
				$variable_line2=0;
				next NEWLINE;
			}
		}
		
		$variable_line2=0;
		next NEWLINE;
	}else{
		$variable_line2=0;
		next NEWLINE;
	}
}
