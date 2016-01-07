<?php
// AMI EVENT READER v0.2 by Jeff Sherk - May 2011
//
// This script will continuously read all the Asterisk AMI events and output them to your browser
//
// This FREE SCRIPT is not copyrighted and is offered AS IS with no guarantees and no warrantees. Do what you want with it!
/////////////////////////////////////////////////
// NOTE: Required for this script to work, and also required is you want to use PHPAGI
/* MODIFY /etc/asterisk/manager.conf and add this (make sure user is asterisk 0664):
    [myamiclient]
    secret=********
    deny=0.0.0.0/0.0.0.0
    permit=127.0.0.1/255.255.255.0
    read = system,call,log,verbose,command,agent,user,config,command,dtmf,reporting,cdr,dialplan,originate
    write = system,call,log,verbose,command,agent,user,config,command,dtmf,reporting,cdr,dialplan,originate
/*
/////////////////////////////////////////////////
// NOTE: Only required if you want to use PHPAGI
/* MODIFY /etc/asterisk/phpagi.conf and add this (make sure user is asterisk 0777):
    [asmanager]
    server=127.0.0.1 ; server to connect to
    port=5038 ; default manager port
    username=myamiclient ; username for login
    secret=******** ; password for login
*/
//username and secret need to match the /etc/asterisk/manager.conf file
$username = 'myamiclient';
$secret = '********';
//DEBUG - Set to TRUE to display a bunch more stuff on the screen
$debug = false;
//Script should run forever, so prevent it from timing out
set_time_limit(0);
//Use fsockopen to connect the same way you would with Telnet
$fp = fsockopen("127.0.0.1", 5038, $errno, $errstr, 30);
//Unsuccessful connect
if (!$fp) {
    echo "$errstr ($errno)\n<br>";
//Successful connect
} else {
    //Login and make sure events are turned off (we will turn them on later).
    fputs($fp,"Action: Login\r\nUsername: ".$username."\r\nSecret: ".$secret."\r\n\r\n");
    fputs($fp,"Action: Events\r\nEventMask: off\r\n\r\n");
    //Check if authentication was successful or not. This duplicates the code from below, but will
    // help code below run a little faster because it will not be checking for this every loop.
    $authentication_failed = true;
    $authentication_loop = true;
    $authentication_time = time();
    $line = '';
    while($authentication_loop) { 
        $read = fread($fp,1); //Read one byte at a time from the socket
        $line .= $read;
        if ("\n" == $read) {
            if ($debug) {
                echo '<br>'.$line;
            }
            flush($fp);
            if ("\r\n" == $line) {
                $authentication_loop = false; //Loop until first blank line is returned.
            }
            if ('Response' == substr($line,0,8) ) {
                if ('Success' == substr($line,10,7) ) {
                    $authentication_failed = false;
                }
            }
            $line = '';        
        }
    }
    if ($authentication_failed) {
        die(' ERROR: Authentication failed!');
    } else {
        if ($debug) {
            echo " --Authentication SUCCESS--\n<br>";
        }
        flush($fp);
    }
    //Get list of current extensions and their current state
    fputs($fp,"Action: Command\r\nCommand: core show hints\r\n\r\n");
    $ext_loop = true;
    $ext_parse = false;
    $line = '';
    $ext_loop_start = 'Registered Asterisk Dial Plan Hints'; //Used to identify where we start parsing
    $ext_loop_end = '-----'; //Used to identify where we stop parsing
    $hold_array = array();
    while($ext_loop) { 
        $read = fread($fp,1); //Read one byte at a time from the socket
        $line .= $read;
        if ("\n" == $read) {
            //Are we at the end of the list? If so, stop parsing and exit WHILE loop
            if ($ext_loop_end == substr($line,0,5) ) {
                $ext_parse = false;
                $ext_loop = false;
            }
            //Parse for EXTEN number, CONTEXT and current STATUS
            if ($ext_parse) {
                $exten = explode('@',$line,2);
                $exten[0] = trim($exten[0]); //Extension number
                $exten[1] = trim($exten[1]);
                $context = explode(' ',$exten[1],5);
                $context[0] = trim($context[0]); //Context
                $state = explode('State:',$exten[1],2);
                $pos = strpos($state[1], ' ');
                $state[1] = substr($state[1],0,$pos); //Current State
                $hold_array[$exten[0]] = array('Status'=>$state[1], 'Context'=>$context[0], 'HoldStart'=>'');
            }
            //Are we at the beginning of list? If so, start parsing on next pass.
            if (strpos($line, $ext_loop_start) ) {
                $ext_parse = true;
            }
            $line = '';
        }
    }
    do_something_with_array($hold_array);
    //Turn Events back ON
    // Use eventmask ON for all events or CALL for call related events only.
    // on; off; system,call,log,verbose,command,agent,user
    fputs($fp,"Action: Events\r\nEventMask: call\r\n\r\n");
//TO DO: Do we need to loop thru entire list of extensions and do an Action: ExtensionState for each??
    //LOOP FOREVER - continuously read data 
    $line = '';
    $event_array = array();
    while(1) {
        $read = fread($fp,1); //Read one byte at a time from the socket
        $line .= $read;
        //Check if we are at the end of a line
        if ("\n" == $read) {
            //Determine when we have reached a blank line which 
            // signals the end of the events info
            if ("\r\n" == $line) {
                //Filter for data related to extensionstatus, linking, unlinking and hangup
                // Do we filter here, or should we just offload all data to another script and let it do the filtering??
                if ('ExtensionStatus'==$event_array['Event'] || 'Link'==$event_array['Event'] || 'Unlink'==$event_array['Event'] || 'Hangup'==$event_array['Event']) {
                    if ($debug) {
                        echo '<pre>';
                        print_r($event_array);
                        echo '</pre>';
                    }
                    flush($fp);
                    //Keep track of each extensions current status
                    // -1 = ExtensionNotFound
                    //  0 = Idle
                    //  1 = InUse
                    //  2 = Busy
                    //  4 = Unavailable
                    //  8 = Ringing
                    // 16 = On Hold 
                    if ('ExtensionStatus'==$event_array['Event']) {
                        $hold_start = '';
                        $status = $event_array['Status'];
                        switch ($event_array['Status']) {
                            case -1:
                                $status = 'ExtensionNotFound';
                                break;
                            case 0:
                                $status = 'Idle';
                                break;
                            case 1:
                                $status = 'InUse';
                                break;
                            case 2:
                                $status = 'Busy';
                                break;
                            case 4:
                                $status = 'Unavailable';
                                break;
                            case 8:
                                $status = 'Ringing';
                                break;
                            case 16:
                                $status = 'Hold';
                                $hold_start = time();
                                break;
                        }
                        $hold_array[$event_array['Exten']] = array('Status'=>$status, 'Context'=>$event_array['Context'], 'HoldStart'=>$hold_start);
                        if ($debug) {
                            echo '<pre>HOLD ';
                            print_r($hold_array);
                            echo '</pre>';
                        }
                        do_something_with_array($hold_array);
                    }
                }
                unset($event_array);
            } else {
                $line_expl = explode(": ", $line, 2);
                $event_array[$line_expl[0]] = trim($line_expl[1]);
            }
            $line = '';
        } //end IF -> Check if we are at the end of a line
    } //end WHILE -> LOOP FOREVER
    fclose($fp); //Will never get here, but looks good to have it!
} //end ELSE -> Successful connect
function do_something_with_array($hold_array) {
    //Display on screen
    //TO DO: you could pass this info on to another script or save in db instead of displaying on screen
    echo '<br><b><u>EXTENSION STATUS</u></b><br>';
    foreach ($hold_array as $key=>$value) {
        echo $key.' '.$value['Status'].' '.$value['HoldStart'].'<br>';
    }
    flush($fp);
}
?>
