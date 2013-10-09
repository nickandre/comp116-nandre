require 'packetfu'
include PacketFu

$num_incidents = 0

def print_alert(type,ip,protocol)
	puts $num_incidents.to_s + ". ALERT: #{type} from #{ip} (#{protocol})!"
	$num_incidents += 1
end

def xmas?(headers)
	return headers == 41
end

def null?(headers)
	return headers == 0
end

def nmap?(payload)
	if payload.scan("Nmap").length > 0
		return true
	end
	return false
end

def password?(payload)
	if payload.scan(/PWD/i).length > 0
		return true
	end
	if payload.scan(/PASS/i).length > 0
		return true
	end
	return false
end

def credit_card(payload)
	if payload.scan(/[345]\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/).length > 0
		puts payload
		return true
	end
	if payload.scan(/6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/).length > 0
		puts payload
		return true
	end
	return false
end

def xss?(payload)
	if payload.scan("POST / HTTP").length > 0 or payload.scan("GET / HTTP").length > 0
		if payload.scan("<script").length > 0
			#if payload.scan("</script").length > 0
				return true
			#end
		end
	end
	return false
end 

stream = PacketFu::Capture.new(:start => true, :iface => ARGV[1] || 'eth0', :promisc => true)

stream.stream.each do | pkt |
	pkt = Packet.parse pkt
	if pkt.is_ip? #Make sure this isn't something strange...
		if pkt.is_tcp?
			data = pkt.payload #.each_byte.map { |b| sprintf(" 0x%02X ",b) }.join
			flags = pkt.tcp_flags
			ip = pkt.ip_header.ip_daddr.to_s
			if xmas?(flags)
				print_alert("XMAS Tree Scan",ip,"TCP")
			elsif null?(flags)
				print_alert("NULL Scan",ip,"TCP")
			elsif nmap?(data)
				print_alert("NMAP Scan",ip,"TCP")
			end
			if password?(data)
				print_alert("Plaintext Password Detected",ip,"TCP")
			end
			if credit_card(data)
				print_alert("Plaintext Credit Card Number Detected",ip,"TCP")
			end
			if xss?(data)
				print_alert("XSS Attack Detected",ip,"HTTP")
			end
		else
			data = pkt.payload
			#printk_alert()
		end
	end
end

