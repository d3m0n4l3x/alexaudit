#!/usr/bin/perl -w
#�߱����������׷�ٹ��ܡ�
$|=1;

sub validate_variable(@$){      #��֤�����Ƿ����������У������򷵻�1�������򷵻�0
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

#��ĳһ��������õ�����--��ʼ��
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
		
		#��ĳһ�����������SQL���������--������
		foreach $everyline2 (@content){
			$variable_line2++;
			if(lc($everyline2)=~/\"[select|insert|update|delete](.*)&([ ]*)$variable([ ]|\n|&)/){
				$variable_lastline=$variable_line2;
				print "LAST: $variable_lastline : $variable\n";
				
				#��ȡ��ʼ���������֮���Ƿ���replace��cint
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
