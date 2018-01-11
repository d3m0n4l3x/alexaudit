#!/usr/bin/perl -w
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

sub replace_blank($){           #替换字符串中存在空格而使用的子函数
	$string_content=shift;
	$string_content=~s/ //g;
	return $string_content;
}

%vulner=(
ExecuteQuery=>"executeQuery",

SelectCase1=>"select count",
SelectCase2=>"select \\\*",                            #select *
SelectCase3=>"select (.*) from",

InsertCase1=>'insert into (.*)\((.*)values',

DeleteCase1=>'delete from (.*)',

UpdateCase1=>'update (.*) set',

RequestCase1=>"request\\(",                                #request(
RequestCase2=>"request\.\(.\*\)\\(",

OpenCase=>"\.open\(.\*\)conn",

ReplaceCase=>'replace\(',

CintCase=>'cint\(',
ClngCase=>'clng\(',

HtmlEncodeCase=>'htmlencode\(',

SqlInjectionCase1a=>"select\(.\*\)request\\(",
SqlInjectionCase1b=>"select\(.\*\)request\.\(.\*\)\\(",

SqlInjectionCase2a=>"update\(.\*\)request\\(",
SqlInjectionCase2b=>"update\(.\*\)request\.\(.\*\)\\(",

SqlInjectionCase3a=>"insert\(.\*\)request\\(",
SqlInjectionCase3b=>"insert\(.\*\)request\.\(.\*\)\\(",

SqlInjectionCase4a=>"drop\(.\*\)request\\(",
SqlInjectionCase4b=>"drop\(.\*\)request\.\(.\*\)\\(",

SqlInjectionCase5a=>"delete\(.\*\)request\\(",
SqlInjectionCase5b=>"delete\(.\*\)request\.\(.\*\)\\(",

CrossSiteScriptCase1=>'<%=request.querystring\(\"(.*)\"\)%>',

AccessDbDisclosureCase1a=>'microsoft\.jet\.oledb(.*)\.mdb',
AccessDbDisclosureCase1b=>'\.mdb(.*)microsoft\.jet\.oledb',
AccessDbDisclosureCase2a=>'microsoft access driver(.*)dbq=(.*)\.mdb',
AccessDbDisclosureCase2b=>'dbq=(.*)\.mdb(.*)microsoft access driver',
);


$logfile = "alexaudit_asp_report.log";
open(LOGIT, ">$logfile");


sub file_import($){
	$filename = shift;
	open(CONTENT, "$filename") || return 0;
	print "=======================$filename=======================\n";
	print LOGIT "=======================$filename=======================\n";
	@content=<CONTENT>;
	close(CONTENT);
	chomp(@content);
	$num=1;
	foreach $tmp (@content){
		foreach $vul (keys %vulner){
			$lc_tmp=lc($tmp);
			$vulner{$vul}=lc($vulner{$vul});
			if($lc_tmp=~/$vulner{$vul}/){
				#$show_vul=$vul;
				#$show_vul=~s/\\//;
				if((lc($vul)=~/sqlinjectioncase(.*)/) || (lc($vul)=~/crosssitescriptcase(.*)/) || (lc($vul)=~/accessdbdisclosurecase(.*)/)){
					$level="ALARM :";
				}else{
					$level="INFO :";
				}
				print $level." found \"$vul\" in $filename : $num : $tmp!\n";
				print LOGIT $level." found \"$vul\" in $filename : $num : $tmp!\n";
			}else{
				next;
			}
		}
	$num++;
	}
	
#------------------------Tracing of Variable-Based
  @variable_database=0;
  undef($variable);
  
  #读某一个变量获得的行数--启始行
  $variable_line=0;
  $variable_line2=0;
  NEWLINE: foreach $everyline (@content){
  	$variable_line++;
  	if(((lc($everyline)=~/(<*)(\%*)([ ]*)(.*)([ ]*)=([ ]*)request\.(.*)\(/)
		|| (lc($everyline)=~/(<*)(\%*)([ ]*)(.*)([ ]*)=([ ]*)request\(/))
		&& (&validate_variable(@variable_database,replace_blank($4))==0)){
  		$variable=replace_blank($4);
  		$variable_headline=$variable_line;
  		push(@variable_database, $variable);
  		#print "BEGIN: $variable_headline : \"$variable\"\n";        #DEBUG
  		
  		#读某一个变量构造成SQL语句后的行数--结束行
  		foreach $everyline2 (@content){                                                 #SQL注入辨别
  			$variable_line2++;
  			if(lc($everyline2)=~/\"(select|insert|update|delete)(.*)&([ ]*)$variable([ ]|\n|&)/){
  				$variable_lastline=$variable_line2;
  				#print "LAST: $variable_lastline : \"$variable\"\n";     #DEBUG
  				
  				#读取启始行与结束行之间是否有replace或cint
  				if(($variable_headline!=0) && ($variable_lastline!=0) && ($variable_lastline>=$variable_headline)){
  					NEWLINE2: for($count=($variable_headline-1) ;$count<=($variable_lastline-1); $count++){
  						if((lc($content[$count])=~/(.*)replace\($variable([ ]*),([ ]*)\"\'\"(.*)/)
  		 				|| (lc($content[$count])=~/(.*)cint\(([ ]*)$variable/)
  		 			  || (lc($content[$count])=~/(.*)clng\(([ ]*)$variable/)){
  		 					#print "PATCH: $count : $content[$count]\n";       #DEBUG
  		 					$variable_line2=0;
  							next NEWLINE;
  						}else{
  							#print "DEBUG : $count : $content[$count]\n";      #DEBUG
  							next NEWLINE2;
  						}
  					}
  					print "EMERGENCY : Tracing of Variable-Based : SQL Injection : \"$variable\"\n";
  					print LOGIT "EMERGENCY : Tracing of Variable-Based : SQL Injection : \"$variable\"\n";
  					$variable_line2=0;
  					next NEWLINE;
  				}
  				$variable_line2=0;
  				next NEWLINE;

  			}elsif(lc($everyline2)=~/\"(update|insert)(.*)&([ ]*)$variable/){          #跨站缺陷辨别
  				$variable_lastline=$variable_line2;
  				#print "LAST: $variable_lastline : \"$variable\"\n";     #DEBUG
  				
  				#读取启始行与结束行之间是否有replace或htmlencode
  				if(($variable_headline!=0) && ($variable_lastline!=0) && ($variable_lastline>=$variable_headline)){
  					NEWLINE3: for($count=($variable_headline-1) ;$count<=($variable_lastline-1); $count++){
  						if((lc($content[$count])=~/(.*)replace\($variable([ ]*),([ ]*)\"\'\"(.*)/)
  		 				|| (lc($content[$count])=~/(.*)htmlencode\(([ ]*)$variable/)){
  		 					#print "PATCH: $count : $content[$count]\n";       #DEBUG
  		 					$variable_line2=0;
  							next NEWLINE;
  						}else{
  							#print "DEBUG : $count : $content[$count]\n";      #DEBUG
  							next NEWLINE3;
  						}
  					}
  					print "EMERGENCY : Tracing of Variable-Based : CrossSiteScript : \"$variable\"\n";
  					print LOGIT "EMERGENCY : Tracing of Variable-Based : CrossSiteScript : \"$variable\"\n";
  					$variable_line2=0;
  					next NEWLINE;
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
#------------------------Tracing of Variable-Based
  	
  }
	return 1;
}


sub read_file(){
	print "File Path : ";
	$file_path = <STDIN>;
	chop($file_path);
	return $file_path;
}


sub read_directory(){
	print "Directory Path : ";
	$directory_path = <STDIN>;
	chop($directory_path);
	$directory_path=$directory_path."\\" if(!($directory_path=~/.*\\/));
	$files_list=sprintf `dir /b /s $directory_path`;
	#print "$files_list\n";
	@files=split(/\n/, $files_list);
	#print "$files[0] $files[1]\n";
	#print "---------------\n@files---------------\n";
	return @files;
}


#main()
START:
print "File(F) or Directory(D) ? ";
$answer = <STDIN>;
chop($answer);

if(uc($answer) eq 'F'){
	$test_file=&read_file();                                         #read file path
	&file_import($test_file);
}else{
	if(uc($answer) eq 'D'){
		@test_files=&read_directory();                                 #read directory path
		foreach $test_file2 (@test_files){
			&file_import($test_file2);
		}
	}else{
		goto START;
	}
}

close(LOGIT);
print "***********************Report in $logfile!***********************\n";

exit(1);