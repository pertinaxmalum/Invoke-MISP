##################################################################################
##############
# ATTRIBUTES #
##############

# Name:
# Function:
# Method:
# Return: 
function Get-AttributesTypes() {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $response = Invoke-RestMethod 'https://{{misp-domain-name}}/attributes/describetypes' -Method 'GET' -Headers $headers

    return $response
}

# Name:
# Function: Not totally clear what the point of this API is 
# Method:
# Return: 
function Get-Attributes() {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $response = Invoke-RestMethod 'https://{{misp-domain-name}}/attributes' -Method 'GET' -Headers $headers

    return $response
}

# Name:
# Function:
# Method:
# Return: 
function Search-Attributes($search) {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $body = $search 

    $response = Invoke-RestMethod 'https://{{misp-domain-name}}/attributes/restSearch' -Method 'POST' -Headers $headers -Body $body

    return $response
}


##################################################################################
#################
#     TAGS      #
#################

# Name:
# Function:
# Method:
# Return: 
function Get-Tags() {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $response = Invoke-RestMethod 'https://{{misp-domain-name}}/tags' -Method 'GET' -Headers $headers

    return $response
}

# Name:
# Function:
# Method:
# Return: 
function Get-TagById($TagID) {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $response = Invoke-RestMethod "https://{{misp-domain-name}}/tags/view/$TagID" -Method 'GET' -Headers $headers

    return $response
}

# Name:
# Function:
# Method:
# Return: 
function Search-Tags($tag) {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $response = Invoke-RestMethod "https://{{misp-domain-name}}/tags/search/$($tag)" -Method 'GET' -Headers $headers

    return $response
}



##################################################################################
##############
#   Events   #
##############

# Doesn't work - think it's too much data?
function Get-Events() {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $response = Invoke-RestMethod "https://{{misp-domain-name}}/events" -Method 'GET' -Headers $headers

    return $response
}

# Name:
# Function:
# Method:
# Return: 
function Search-Events($search) {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $body = $search 

    $response = Invoke-RestMethod 'https://{{misp-domain-name}}/events/restSearch' -Method 'POST' -Headers $headers -Body $body

    return $response
}

# Name:
# Function:
# Method:
# Return: 
function Get-EventById($EventID) {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $response = Invoke-RestMethod "https://{{misp-domain-name}}/events/view/$EventID" -Method 'GET' -Headers $headers

    return $response
}

##################################################################################
##############
#   Feeds    #
##############

# We do not seem to have permissions to view feeds. Maybe not in use?

# Name:
# Function: 
# Method:
# Return: 
function Get-Feeds() {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $response = Invoke-RestMethod 'https://{{misp-domain-name}}/feeds' -Method 'GET' -Headers $headers

    return $response
}

# Name:
# Function: 
# Method:
# Return: 
function Get-FeedsById($FeedID) {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $response = Invoke-RestMethod "https://{{misp-domain-name}}/feeds/view/$FeedID" -Method 'GET' -Headers $headers

    return $response
}

# Name:
# Function: 
# Method:
# Return: 
function Get-FeedByID($FeedID) {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $response = Invoke-RestMethod "https://{{misp-domain-name}}/feeds/fetchFromFeed/$FeedID" -Method 'POST' -Headers $headers

    return $response
}

# Name:
# Function: 
# Method:
# Return: 
function Get-AllFeeds() {
    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Accept", "application/json")
    $headers.Add("Content-Type", "application/json")
    $headers.Add("Authorization", "$($env:MISPAPIKEY)")

    $response = Invoke-RestMethod "https://{{misp-domain-name}}/feeds/fetchFromAllFeeds" -Method 'POST' -Headers $headers

    return $response
}
