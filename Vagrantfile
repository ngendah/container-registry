# -*- mode: ruby -*-
# vi: set ft=ruby :
#
require 'openssl'

def generate_certificate(issuer_name, domain_name, path, filename: "ca")
  name = OpenSSL::X509::Name.parse(issuer_name)
  pkey = OpenSSL::PKey::RSA.new(4096)
  cert = OpenSSL::X509::Certificate.new
  cert.serial = 0
  cert.version = 2
  cert.issuer = name
  cert.subject = name
  cert.public_key = pkey.public_key
  cert.not_before = Time.now
  cert.not_after = Time.now + (365 * 24 * 60 * 60)
  extension_factory = OpenSSL::X509::ExtensionFactory.new cert, cert
  cert.add_extension \
    extension_factory.create_extension('subjectAltName', "DNS:#{domain_name}")
  cert.add_extension \
    extension_factory.create_extension('subjectKeyIdentifier', 'hash')
  cert.add_extension \
    extension_factory.create_extension('basicConstraints', 'CA:TRUE', true)
  cert.add_extension \
    extension_factory.create_extension('keyUsage', 'cRLSign,keyCertSign', true)
  cert.sign(pkey, OpenSSL::Digest::SHA256.new)
  File.write("#{path}/#{filename}.crt", cert.to_s, 0, perm: 0o600)
  File.write("#{path}/#{filename}.key", pkey.to_s, 0, perm: 0o600)
rescue Exception => e
  puts "Unable to generate certificate, manually generate with the command"
  puts "openssl req -newkey rsa:4096 -nodes -sha256 -keyout '#{path}/#{filename}.key' "\
    "-subj '#{issuer_name}' "\
    "-addext 'subjectAltName=DNS:#{domain_name}' -x509 -days 365 "\
    "-out '#{path}/#{filename}.crt'"
  false
end

Vagrant.configure("2") do |config|
  # The most common configuration options are documented and commented below.
  # For a complete reference, please see the online documentation at
  # https://docs.vagrantup.com.

  config.vm.box = 'ubuntu/jammy64'
  config.vm.box_check_update = false
  config.vm.provider :virtualbox do |vb|
    vb.cpus = 2
    vb.memory = '1024'
  end
  certs_dir = 'registry/roles/registry2/files/.tls'
  FileUtils.mkdir_p certs_dir
  if !generate_certificate('/CN=cubcr.io/O=cub', 'cubcr.io', certs_dir)
    abort
  end
  config.vm.define 'container_registry', priviledged: false do |vm|
    config.vm.hostname = 'cubcr'
    config.vm.network :private_network, ip: '192.168.56.20'
    config.vm.provision :ansible do |ansible|
      ansible.playbook = 'registry/main.yml'
      ansible.extra_vars = {
        user: {
          name: 'test',
          passwd: 'passwd#',
        }
      }
    end
  end
end

