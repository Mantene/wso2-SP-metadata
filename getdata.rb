#
# This script will automatically generate shibboleth 3 compliant service provider metadata xml files from
# service provider data set up in WSO2's API Manager.
# This requires the use of the resource.war file that enabled the wso2 api manager Registry REST api
# found here: https://docs.wso2.com/download/attachments/92520268/resource.war?version=1&modificationDate=1520328119000&api=v2
# With documentation here: https://docs.wso2.com/display/AM250/Using+the+Registry+REST+API
#
require 'rest-client'
require 'json'
require 'keystores'

#### Configuration Variables ####
user = #put your wso2 admin username here
password = #put your wso2 admin password here
keystore = #put the path to your keystore here (usually wso2carbon.jks)
keyalias = #put the alias of the cert you want to use here (default is wso2carbon for wso2carbon.jks)
key_store_password = #put your keystore password here (typically wso2carbon for wso2carbon.jks)


artifacturl = 'https://localhost:9443/resource/1.0.0/artifact/_system/config/repository/identity/SAMLSSO'
artifactresp = RestClient::Request.execute method: :get, url: artifacturl, user: user, password: password
artifactdata = artifactresp.to_s.tr('[]', '').tr('""','')
artifactdata = artifactdata.split(",")
puts artifactdata
artifactdata.each do |key|
	puts #{key}
	url = "https://localhost:9443/resource/1.0.0/properties?path=#{key}"
	puts url
	response = RestClient::Request.execute method: :get, url: url, user: user, password: password
	data = JSON.parse(response)
	remap = data.map {|x| x.values}
	mapped = Hash.new
	remap.each do |key, value|
	  mapped["#{key}"] = "#{value}".tr('[]', '').tr('""','')
	end

	keystore = OpenSSL::JKS.new
	keystore.load(keystore, key_store_password)
	certificate = keystore.get_certificate(keyalias)
	x509 = certificate.to_s
	x509 = x509.sub("-----BEGIN CERTIFICATE-----", "")
	x509 = x509.sub("-----END CERTIFICATE-----", "").strip
layout =<<EOS
<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" validUntil="2029-08-18T06:13:48Z" cacheDuration="PT604800S" entityID="#{mapped['Issuer']}">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="#{mapped['signingAlgorithm']}">
        <ds:X509Data>
          <ds:X509Certificate> #{x509}
    	</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="#{mapped['signingAlgorithm']}">
        <ds:X509Data>
          <ds:X509Certificate> #{x509}
    	</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="#{mapped['SAMLSSOAssertionConsumerURLs']}"/>
    <md:NameIDFormat #{mapped['NameIDFormat']}/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="#{mapped['SAMLSSOAssertionConsumerURLs']}" index="1"/>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
EOS
output = File.open( "#{mapped['Issuer']}.xml","w" )
output << layout
output.close
end
