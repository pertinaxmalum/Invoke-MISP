Import-Module "$PSScriptRoot\MISP-Utils.psm1" 

Import-Module "$PSScriptRoot\MISP-APICalls.psm1" 

function Invoke-MISP {

<#
        .SYNOPSIS
                
        .DESCRIPTION
            			
		.PARAMETER 
            
        .PARAMETER 
            
        .PARAMETER 

        .EXAMPLE

        .EXAMPLE
            
#>

    [CmdletBinding()]
    Param (

    [Parameter(Mandatory = $false, Position = 0)]
    [Switch] $ListTags, # needs an error message here

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateScript({
            #TODO - adds in keys we'd want in the same fashion as below
            # 
            if ("type" -in $_.Keys) { # this just checks if the key is 'type' and tells you what types are allowed, btw
                if ($_['type'] -notin "md5","sha1","sha256","filename","pdb","filename|md5","filename|sha1","filename|sha256","ip-src","ip-dst","hostname","domain","domain|ip","email","email-src","eppn","email-dst","email-subject","email-attachment","email-body","float","git-commit-id","url","http-method","user-agent","ja3-fingerprint-md5","jarm-fingerprint","favicon-mmh3","hassh-md5","hasshserver-md5","regkey","regkey|value","AS","snort","bro","zeek","community-id","pattern-in-file","pattern-in-traffic","pattern-in-memory","pattern-filename","pgp-public-key","pgp-private-key","yara","stix2-pattern","sigma","gene","kusto-query","mime-type","identity-card-number","cookie","vulnerability","cpe","weakness","attachment","malware-sample","link","comment","text","hex","other","named pipe","mutex","process-state","target-user","target-email","target-machine","target-org","target-location","target-external","btc","dash","xmr","iban","bic","bank-account-nr","aba-rtn","bin","cc-number","prtn","phone-number","threat-actor","campaign-name","campaign-id","malware-type","uri","authentihash","vhash","ssdeep","imphash","telfhash","pehash","impfuzzy","sha224","sha384","sha512","sha512/224","sha512/256","sha3-224","sha3-256","sha3-384","sha3-512","tlsh","cdhash","filename|authentihash","filename|vhash","filename|ssdeep","filename|imphash","filename|impfuzzy","filename|pehash","filename|sha224","filename|sha384","filename|sha512","filename|sha512/224","filename|sha512/256","filename|sha3-224","filename|sha3-256","filename|sha3-384","filename|sha3-512","filename|tlsh","windows-scheduled-task","windows-service-name","windows-service-displayname","whois-registrant-email","whois-registrant-phone","whois-registrant-name","whois-registrant-org","whois-registrar","whois-creation-date","x509-fingerprint-sha1","x509-fingerprint-md5","x509-fingerprint-sha256","dns-soa-email","size-in-bytes","counter","datetime","port","ip-dst|port","ip-src|port","hostname|port","mac-address","mac-eui-64","email-dst-display-name","email-src-display-name","email-header","email-reply-to","email-x-mailer","email-mime-boundary","email-thread-index","email-message-id","github-username","github-repository","github-organisation","jabber-id","twitter-id","dkim","dkim-signature","first-name","middle-name","last-name","full-name","date-of-birth","place-of-birth","gender","passport-number","passport-country","passport-expiration","redress-number","nationality","visa-number","issue-date-of-the-visa","primary-residence","country-of-residence","special-service-request","frequent-flyer-number","travel-details","payment-details","place-port-of-original-embarkation","place-port-of-clearance","place-port-of-onward-foreign-destination","passenger-name-record-locator-number","mobile-application-id","chrome-extension-id","cortex","boolean","anonymised") {
                    Write-Host "[!] Invalid key '$($_['type'])'. Allowed values: `nmd5`nsha1`nsha256`nfilename`npdb`nfilename|md5`nfilename|sha1`nfilename|sha256`nip-src`nip-dst`nhostname`ndomain`ndomain|ip`nemail`nemail-src`neppn`nemail-dst`nemail-subject`nemail-attachment`nemail-body`nfloat`ngit-commit-id`nurl`nhttp-method`nuser-agent`nja3-fingerprint-md5`njarm-fingerprint`nfavicon-mmh3`nhassh-md5`nhasshserver-md5`nregkey`nregkey|value`nAS`nsnort`nbro`nzeek`ncommunity-id`npattern-in-file`npattern-in-traffic`npattern-in-memory`npattern-filename`npgp-public-key`npgp-private-key`nyara`nstix2-pattern`nsigma`ngene`nkusto-query`nmime-type`nidentity-card-number`ncookie`nvulnerability`ncpe`nweakness`nattachment`nmalware-sample`nlink`ncomment`ntext`nhex`nother`nnamed pipe`nmutex`nprocess-state`ntarget-user`ntarget-email`ntarget-machine`ntarget-org`ntarget-location`ntarget-external`nbtc`ndash`nxmr`niban`nbic`nbank-account-nr`naba-rtn`nbin`ncc-number`nprtn`nphone-number`nthreat-actor`ncampaign-name`ncampaign-id`nmalware-type`nuri`nauthentihash`nvhash`nssdeep`nimphash`ntelfhash`npehash`nimpfuzzy`nsha224`nsha384`nsha512`nsha512/224`nsha512/256`nsha3-224`nsha3-256`nsha3-384`nsha3-512`ntlsh`ncdhash`nfilename|authentihash`nfilename|vhash`nfilename|ssdeep`nfilename|imphash`nfilename|impfuzzy`nfilename|pehash`nfilename|sha224`nfilename|sha384`nfilename|sha512`nfilename|sha512/224`nfilename|sha512/256`nfilename|sha3-224`nfilename|sha3-256`nfilename|sha3-384`nfilename|sha3-512`nfilename|tlsh`nwindows-scheduled-task`nwindows-service-name`nwindows-service-displayname`nwhois-registrant-email`nwhois-registrant-phone`nwhois-registrant-name`nwhois-registrant-org`nwhois-registrar`nwhois-creation-date`nx509-fingerprint-sha1`nx509-fingerprint-md5`nx509-fingerprint-sha256`ndns-soa-email`nsize-in-bytes`ncounter`ndatetime`nport`nip-dst|port`nip-src|port`nhostname|port`nmac-address`nmac-eui-64`nemail-dst-display-name`nemail-src-display-name`nemail-header`nemail-reply-to`nemail-x-mailer`nemail-mime-boundary`nemail-thread-index`nemail-message-id`ngithub-username`ngithub-repository`ngithub-organisation`njabber-id`ntwitter-id`ndkim`ndkim-signature`nfirst-name`nmiddle-name`nlast-name`nfull-name`ndate-of-birth`nplace-of-birth`ngender`npassport-number`npassport-country`npassport-expiration`nredress-number`nnationality`nvisa-number`nissue-date-of-the-visa`nprimary-residence`ncountry-of-residence`nspecial-service-request`nfrequent-flyer-number`ntravel-details`npayment-details`nplace-port-of-original-embarkation`nplace-port-of-clearance`nplace-port-of-onward-foreign-destination`npassenger-name-record-locator-number`nmobile-application-id`nchrome-extension-id`ncortex`nboolean`nanonymised." -ForegroundColor yellow
                    break
                }
            }
            
            foreach ($key in $_.keys) {
                if($key -notin "metadata","eventid","tag","threat_level_id","limit","category","page","returnFormat","timestamp","to","withAttachments","published","type","date","eventinfo","from","sharinggroup","org","publish_timestamp","excludeLocalTags","uuid","searchall","enforceWarninglist","last","tags","sgReferenceOnly","event_tags","value","to_ids") { 
                    Write-Host "[!] Invalid key, must be: `nmetadata`neventid`ntag`nthreat_level_id`nlimit`ncategory`npage`nreturnFormat`ntimestamp`nto`nwithAttachments`npublished`ntype`ndate`neventinfo`nfrom`nsharinggroup`norg`npublish_timestamp`nexcludeLocalTags`nuuid`nsearchall`nenforceWarninglist`nlast`ntags`nsgReferenceOnly`nevent_tags`nvalue`nto_ids" -ForegroundColor yellow
                    throw
                    
                }
            }
            return $true
        })]
    [hashtable] $SearchEvents,

    [Parameter(Mandatory = $false, Position = 0)]
    [String] $SearchTagByName,

    [Parameter(Mandatory = $false, Position = 0)]
    [String] $GetTagById,

    [Parameter(Mandatory = $false, Position = 0)]
    [String] $EventID,
    
    [Parameter(Mandatory = $false, Position = 0)]
    [Int32] $Page = 1,

    [Parameter(Mandatory = $false, Position = 0)]
    [Int32] $Limit = 200,

    [Parameter(Mandatory = $false, Position = 0)]
    [Switch] $Attributes = $false,

    [Parameter(Mandatory = $false, Position = 0)]
    [Switch] $GetAllResults = $true,

    [Parameter(Mandatory = $false, Position = 0)]
    [System.IO.FileInfo]$cliXML,

    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet("Attributes","Tags","All","RawData", IgnoreCase = $true)]
    [String] $ReturnFormat = "RawData"

    )


        Import-Module "$PSScriptRoot\MISP-Utils.psm1" 

        Import-Module "$PSScriptRoot\MISP-APICalls.psm1" 

        if (!$cliXML) { $cliXML = "$PSScriptRoot\details.xml" }

        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

        if ($onServer) {
            $proxy = '{{redacted}}'

            [system.net.webrequest]::defaultwebproxy = new-object system.net.webproxy($proxy)
            [system.net.webrequest]::defaultwebproxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
            [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
        }

        function Get-Cred ($cliXML) {
    
            $cred = Import-Clixml $cliXML

            $cred_securestring = $cred | ConvertTo-SecureString

            $secure_token = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($cred_securestring)

            return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($secure_token)

        }

        # Variarables
        $env:MISPAPIKEY = Get-Cred -cliXML $cliXML

        $root_event_search_object = [psobject]@{
        "returnFormat" = "json" # Mandatory: json csv - "json" "xml" "csv" "text" "stix" "stix2" "stix-json" "attack" "attack-sightings" "cache" "count" "hashes" "netfilter" "opendata" "openioc" "rpz" "snort" "suricata" "yara" "yara-json"
        "page" = "" # int >=0 gets a particular page number (number of entries per page decided by limit)
        "limit" = "" # int >= 1 sets limit of entries per page
        "value" = "" # string <= 131071 characters, attribute value
        "type" = "" # string <= 100 characters, attribute type "md5" "sha1" "sha256" "filename" "pdb" "filename|md5" "filename|sha1" "filename|sha256" "ip-src" "ip-dst" "hostname" "domain" "domain|ip" "email" "email-src" "eppn" "email-dst" "email-subject" "email-attachment" "email-body" "float" "git-commit-id" "url" "http-method" "user-agent" "ja3-fingerprint-md5" "jarm-fingerprint" "favicon-mmh3" "hassh-md5" "hasshserver-md5" "regkey" "regkey|value" "AS" "snort" "bro" "zeek" "community-id" "pattern-in-file" "pattern-in-traffic" "pattern-in-memory" "pattern-filename" "pgp-public-key" "pgp-private-key" "yara" "stix2-pattern" "sigma" "gene" "kusto-query" "mime-type" "identity-card-number" "cookie" "vulnerability" "cpe" "weakness" "attachment" "malware-sample" "link" "comment" "text" "hex" "other" "named pipe" "mutex" "process-state" "target-user" "target-email" "target-machine" "target-org" "target-location" "target-external" "btc" "dash" "xmr" "iban" "bic" "bank-account-nr" "aba-rtn" "bin" "cc-number" "prtn" "phone-number" "threat-actor" "campaign-name" "campaign-id" "malware-type" "uri" "authentihash" "vhash" "ssdeep" "imphash" "telfhash" "pehash" "impfuzzy" "sha224" "sha384" "sha512" "sha512/224" "sha512/256" "sha3-224" "sha3-256" "sha3-384" "sha3-512" "tlsh" "cdhash" "filename|authentihash" "filename|vhash" "filename|ssdeep" "filename|imphash" "filename|impfuzzy" "filename|pehash" "filename|sha224" "filename|sha384" "filename|sha512" "filename|sha512/224" "filename|sha512/256" "filename|sha3-224" "filename|sha3-256" "filename|sha3-384" "filename|sha3-512" "filename|tlsh" "windows-scheduled-task" "windows-service-name" "windows-service-displayname" "whois-registrant-email" "whois-registrant-phone" "whois-registrant-name" "whois-registrant-org" "whois-registrar" "whois-creation-date" "x509-fingerprint-sha1" "x509-fingerprint-md5" "x509-fingerprint-sha256" "dns-soa-email" "size-in-bytes" "counter" "datetime" "port" "ip-dst|port" "ip-src|port" "hostname|port" "mac-address" "mac-eui-64" "email-dst-display-name" "email-src-display-name" "email-header" "email-reply-to" "email-x-mailer" "email-mime-boundary" "email-thread-index" "email-message-id" "github-username" "github-repository" "github-organisation" "jabber-id" "twitter-id" "dkim" "dkim-signature" "first-name" "middle-name" "last-name" "full-name" "date-of-birth" "place-of-birth" "gender" "passport-number" "passport-country" "passport-expiration" "redress-number" "nationality" "visa-number" "issue-date-of-the-visa" "primary-residence" "country-of-residence" "special-service-request" "frequent-flyer-number" "travel-details" "payment-details" "place-port-of-original-embarkation" "place-port-of-clearance" "place-port-of-onward-foreign-destination" "passenger-name-record-locator-number" "mobile-application-id" "chrome-extension-id" "cortex" "boolean" "anonymised"
        "category" = "" # string <= 255 chars, Attribute Category "Internal reference" "Targeting data" "Antivirus detection" "Payload delivery" "Artifacts dropped" "Payload installation" "Persistence mechanism" "Network activity" "Payload type" "Attribution" "External analysis" "Financial fraud" "Support Tool" "Social network" "Person" "Other"
        "org" = "" # String
        "tag" = "" # string <= 255 chars
        "tags" = "" # Array of strings
        "event_tags" = "" # Array of strings
        "searchall" = "" # string - Search events by matching any tag names, event descriptions, attribute values or attribute comments
        "date" = "" # string - You can use any of the valid time related filters (examples: 7d, timestamps, [14d, 7d] for ranges, etc.)
        "from" = "" # String You can use any of the valid time related filters (examples: 7d, timestamps, [14d, 7d] for ranges, etc.)
        "to" = "" # string You can use any of the valid time related filters (examples: 7d, timestamps, [14d, 7d] for ranges, etc.)
        "last" = "" # int or string - Events published within the last x amount of time, where x can be defined in days, hours, minutes (for example 5d or 12h or 30m), ISO 8601 datetime format or timestamp
        "eventid" = "" # string <= 10 chars
        "withAttachments" = "" # boolean (default: false) Extends the response with the base64 representation of the attachment, if there is one
        "sharinggroup" = "" #Array of strings - Sharing group ID(s), either as single string or list of IDs
        "metadata" = "" # Boolean - Will only return the metadata of the given query scope, contained data is omitted.
        "uuid" = "" # String - <= 36 characters
        "published" = "" # Boolean - default: false
        "publish_timestamp" = "" # String - Timestamp default: 0 ^\d+$
        "timestamp" = "" # # String - Timestamp default: 0 ^\d+$
        "enforceWarninglist" = "" #boolean - Should the warning list be enforced. Adds blocked field for matching attributes
        "sgReferenceOnly" = "" # boolean - Will only return the sharing group ID
        "eventinfo" = "" # 
        "excludeLocalTags" = "" # boolean - Exclude local tags from the export
        "threat_level_id" = "" # string 1 - High, 2 - Medium, 3 - Low, 4 - Undefined
        "to_ids" = "" # boolean (ToIDSRestSearchFlag) - Specifies if value to be taken into IDS
    }

    

    ###########
    # Process #
    ###########

    if ($ListTags) {
        $return_object = Get-Tags
    }
    
    if ($GetTagById) {
        $return_object = Get-TagById -TagID $GetTagById
    }
    
    if ($SearchTagByName) {
        $return_object = Search-Tags -tag $SearchTagByName
    }

    if ($SearchEvents) {

        $return_object = @()


        foreach ($item in $SearchEvents.GetEnumerator() ) {

            $root_event_search_object[$item.key] = $item.Value

            # debug default values
            $root_event_search_object['limit'] = $limit
            $root_event_search_object['page'] = $page

        }

        $json_string_for_search = Convert-ObjectToJson -Object_to_JSONify $root_event_search_object

        $return_object += Search-Events -search $json_string_for_search

        if ($return_object.response) { $more_content = $true } else { $more_content = $false }

        While($GetAllResults -and $more_content) {

            $json_object_for_pagination = $json_string_for_search | ConvertFrom-Json

            $json_object_for_pagination.page += 1

            $json_string_for_search = $json_object_for_pagination | ConvertTo-Json

            $next_page_response = Search-Events -search $json_string_for_search

            if ($next_page_response.response) { 
                $more_content = $true; 
                $return_object += $next_page_response 
            } else { $more_content = $false }

            
        }


    }

    if ($EventID) {
        
        $return_object = Get-EventById -EventID $EventID

    }
    

    #######
    # end #
    #######

    switch ($ReturnFormat) {
        Attributes {$return_object.response.event.Attribute}
        Tags {$return_object.response.event.tag} 
        rawdata {if($return_object.response.event) {$return_object.response.event} else {$return_object}}
        default {$return_object.response.event}
        all { 
            $fullTabularReturnObject = @()
            
            foreach ($response in $return_object.response.event) {
                $eventObjectToAddToReturnObject = [pscustomobject]@{}
            
                Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "eventId" -Value $response.id
                Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "info" -Value $response.info

                # Add attributes
                # Attributes can sometimes be tucked away in $.Object.Attribute
                $counter = 1
                if($response.Attribute) {
                    foreach ($attributeToAdd in $response.Attribute) {
                        Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "Att$($counter)id" -Value $attributeToAdd.id
                        Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "Att$($counter)type" -Value $attributeToAdd.type
                        Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "Att$($counter)to_ids" -Value $attributeToAdd.to_ids
                        Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "Att$($counter)comment" -Value $attributeToAdd.comment
                        Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "Att$($counter)value" -Value $attributeToAdd.value
                        $counter++
                    }
                } elseif ($response.Object.Attribute) {
                    foreach ($attributeToAdd in $response.Object.Attribute) {
                        Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "Att$($counter)id" -Value $attributeToAdd.id
                        Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "Att$($counter)type" -Value $attributeToAdd.type
                        Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "Att$($counter)to_ids" -Value $attributeToAdd.to_ids
                        Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "Att$($counter)comment" -Value $attributeToAdd.comment
                        Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "Att$($counter)value" -Value $attributeToAdd.value
                        $counter++
                    }
                }

                # Add tags
                $counter = 1
                foreach ($attributeToAdd in $response.tag) {
                    Add-Member -InputObject $eventObjectToAddToReturnObject -MemberType NoteProperty -Name "Tag$($counter)" -Value $attributeToAdd.name
                    $counter++
                }

                $fullTabularReturnObject += $eventObjectToAddToReturnObject
            }
        
            # return
            $fullTabularReturnObject
        }
    }

    
    $env:MISPAPIKEY = $null
 
}

<#
TODO:
    - Add a 'show search options' feature that will show what fields can be entered. 
    it should be in the documentation too, but a switch to display just that might be handy
    Best bet would be to have it just print the hash table probably but with the field values as values

    - Move the allowed Type values into a JSON array that the write host uses rather than having it raw like that, if that'll work
    - Do an allow/check for search paramaters too
#>
