param location string = 'westeurope'
resource sa 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'fixture'
  location: location
}
