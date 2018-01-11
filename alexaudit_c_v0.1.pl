#!/usr/bin/perl -w
$|=1;


%vulner=(
getsCase=>'gets\(',
strcpyCase=>'strcpy\(',
strcatCase=>'strcat\(',
sprintfCase=>'sprintf\(',
scanfCase=>'scanf\(',
sscanfCase=>'sscanf\(',
fscanfCase=>'fscanf\(',
vfscanfCase=>'vfscanf\(',
vsprintfCase=>'vsprintf\(',
vscanfCase=>'vscanf\(',
vsscanfCase=>'vsscanf\(',
streaddCase=>'streadd\(',
strecpyCase=>'strecpy\(',
strtrnsCase=>'strtrns\(',
realpathCase=>'realpath\(',
syslogCase=>'syslog\(',
getoptCase=>'getopt\(',
getopt_longCase=>'getopt_long\(',
getpassCase=>'getpass\(',
getcharCase=>'getchar\(',
fgetcCase=>'fgetc\(',
getcCase=>'getc\(',
readCase=>'read\(',
bcopyCase=>'bcopy\(',
fgetsCase=>'fgets\(',
memcpyCase=>'memcpy\(',
snprintfCase=>'snprintf\(',
strccpyCase=>'strccpy\(',
strcaddCase=>'strcadd\(',
strncpyCase=>'strncpy\(',
vsnprintfCase=>'vsnprintf\(',

wcscpyCase=>'wcscpy\(',
_tcscpyCase=>'_tcscpy\(',
_mbscpyCase=>'_mbscpy\(',
StrCpyCase=>'StrCpy\(',
StrCpyACase=>'StrCpyA\(',
StrCpyWCase=>'StrCpyW\(',
lstrcpyCase=>'lstrcpy\(',
lstrcpyACase=>'lstrcpyA\(',
lstrcpyWCase=>'lstrcpyW\(',
strcpyACase=>'strcpyA\(',
strcpyWCase=>'strcpyW\(',
_tccpyCase=>'_tccpy\(',
_mbccpyCase=>'_mbccpy\(',
wcscatCase=>'wcscat\(',
_tcscatCase=>'_tcscat\(',
_mbscatCase=>'_mbscat\(',
StrCatCase=>'StrCat\(',
StrCatACase=>'StrCatA\(',
StrCatWCase=>'StrCatW\(',
lstrcatCase=>'lstrcat\(',
lstrcatACase=>'lstrcatA\(',
lstrcatWCase=>'lstrcatW\(',
StrCatBuffWCase=>'StrCatBuffW\(',
StrCatBuffCase=>'StrCatBuff\(',
StrCatBuffACase=>'StrCatBuffA\(',
StrCatChainWCase=>'StrCatChainW\(',
strcatACase=>'strcatA\(',
strcatWCase=>'strcatW\(',
_tccatCase=>'_tccat\(',
_mbccatCase=>'_mbccat\(',
wnsprintfCase=>'wnsprintf\(',
wnsprintfACase=>'wnsprintfA\(',
wnsprintfWCase=>'wnsprintfW\(',
sprintfWCase=>'sprintfW\(',
sprintfACase=>'sprintfA\(',
wsprintfCase=>'wsprintf\(',
wsprintfWCase=>'wsprintfW\(',
wsprintfACase=>'wsprintfA\(',
swprintfCase=>'swprintf\(',
_stprintfCase=>'_stprintf\(',
);

$logfile = "alexaudit_c_report.log";
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
			#$lc_tmp=lc($tmp);
			#$vulner{$vul}=lc($vulner{$vul});
			if($tmp=~/$vulner{$vul}/){
				#$show_vul=$vul;
				#$show_vul=~s/\\//;
				if((lc($vul)=~/getchar(.*)/) || (lc($vul)=~/fgetc(.*)/)  || (lc($vul)=~/getc(.*)/)
				 || (lc($vul)=~/read(.*)/)){
					$level="ALARM :";                          #中级风险
				}else{
					if((lc($vul)=~/bcopy(.*)/) || (lc($vul)=~/fgets(.*)/) || (lc($vul)=~/memcpy(.*)/)
					 || (lc($vul)=~/snprintf(.*)/) || (lc($vul)=~/strccpy(.*)/) || (lc($vul)=~/strcadd(.*)/)
				   || (lc($vul)=~/strncpy(.*)/) || (lc($vul)=~/vsnprintf(.*)/)){
						$level="INFO :";                         #低风险
					}else{
						$level="EMERGENCY :";                    #高风险
					}
				}
				print $level." found \"$vul\" in $filename : $num : $tmp!\n";
				print LOGIT $level." found \"$vul\" in $filename : $num : $tmp!\n";
			}else{
				next;
			}
		}
	$num++;
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