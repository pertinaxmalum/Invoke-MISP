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
}

function Convert-ObjectToJson($Object_to_JSONify) {
    # Assumes hashtable atm

    # not using the below way as it return a Dictionary entry which doesn't convert neatly to JSON - not a bad solution tho!
    #$non_null_values_object = [hashtable]($PsObject.GetEnumerator() | ?{$_.value})

    # remove empty values
    $keys_to_remove = @() ; $Object_to_JSONify.Keys | %{if($Object_to_JSONify[$_] -in ("",$null)) {$keys_to_remove += $_}}

    $keys_to_remove | %{$Object_to_JSONify.Remove($_)}
    
    # convert to json
    $json_object = $Object_to_JSONify | ConvertTo-Json

    # put on a single line, to be safe
    $processed_object_now_json = ($json_object) -replace "`n",""

    return $processed_object_now_json
}

