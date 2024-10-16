param location string = resourceGroup().location
param workspaceName string = 'snapshotsiem-prod1'
param groupName string = 'Security Analyst Lab'

resource logAnalyticsWorkspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: workspaceName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
  }
}

resource sentinel 'Microsoft.SecurityInsights/workspaces/providers/OnboardingStates@2021-03-01-preview' = {
  name: 'default'
  parent: logAnalyticsWorkspace
  properties: {
    onboardingState: 'Onboarded'
  }
}

resource securityGroup 'Microsoft.Authorization/roleAssignments@2020-04-01-preview' = {
  name: guid(resourceGroup().id, groupName)
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '8d289c81-587b-46d4-8554-54e1e4d3b7d9') // Sentinel Responder role
    principalId: securityGroup.id
    principalType: 'Group'
  }
}

resource entraGroup 'Microsoft.Graph/groups@1.0' = {
  name: groupName
  properties: {
    displayName: groupName
    mailEnabled: false
    securityEnabled: true
    mailNickname: groupName
  }
}

output workspaceId string = logAnalyticsWorkspace.id
output sentinelId string = sentinel.id
output groupId string = entraGroup.id
