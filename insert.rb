require 'json'
require 'csv'
require 'sqlite3'
def setup
  db = SQLite3::Database.new('cowrie.db')
  db.execute("
		create table ips (
		ip varchar(30),
		count int
  );")

  db.execute("
		create table failed_usernames (
		username varchar(30),
		count int
  );")

  db.execute("
		create table success_usernames (
		username varchar(30),
		count int
  );")
end

def sort(data)
  data.sort_by { |_key, value| value }.reverse
end
ip = {}
failed_usr  = {}
success_usr = {}
File.open('cowrie.json', 'r').each_line do |line|
  j = JSON.parse(line)
  if j['eventid'].split('.')[1] == 'login'
    ip[j['src_ip']] = if !ip.key?(j['src_ip'])
                        1
                      else
                        ip[j['src_ip']] += 1
                      end
  end
  if j['eventid'] == 'cowrie.login.failed'
    failed_usr[j['username']] = if !failed_usr.key?(j['username'])
                                  1
                                else
                                  failed_usr[j['username']] += 1
                                end
  end
  next unless j['eventid'] == 'cowrie.login.success'

  success_usr[j['username']] = (failed_usr[j['username']] += 1 if failed_usr.key?(j['username']))
end

# failed users
f_usr = sort(failed_usr)
s_usr = sort(success_usr)
ip_logins = sort(ip)
ips = []
ip_logins.each do |k|
  ips << [k[0], k[1]]
end

failed_usrnames = []
f_usr.each do |fu|
  failed_usrnames << [fu[0], fu[1]]
end

success_usrnames = []
s_usr.each do |su|
  success_usrnames << [su[0], su[1]]
end

setup unless File.exist?('cowrie.db')

c_db = SQLite3::Database.new('cowrie.db')

failed_usrnames.each do |u, c|
  uname_zero = c_db.prepare("SELECT COUNT(username) from failed_usernames WHERE
	 username = :uname")
  uname_zero.execute('uname' => u)
  u_count = nil
  uname_zero = uname_zero.each { |i| u_count = i }
  uname_zero.close
  if u_count.shift.equal?(0)
    c_db.execute("INSERT INTO failed_usernames (username, count)
		VALUES(?, ?)", [u, c])
  else
    update_count = c_db.prepare("UPDATE failed_usernames SET count = count +
		 :count WHERE username = :uname")
    update_count.execute({ "count": c, "uname": u })
    update_count.close
  end
end

success_usrnames.each do |u, c|
  uname_zero = c_db.prepare("SELECT COUNT(username) from success_usernames WHERE
	 username = :uname")
  uname_zero.execute('uname' => u)
  result = nil
  uname_zero = uname_zero.each { |i| result = i }
  uname_zero.close
  if result.shift.equal?(0)
    c_db.execute("INSERT INTO success_usernames (username, count)
		VALUES(?, ?)", [u, c])
  else
    update_success_count = c_db.prepare("UPDATE success_usernames SET count = count +
			:count WHERE username = :uname")
    update_success_count.execute({ "count": c, "uname": u })
    update_success_count.close
  end
end

ips.each do |i, c|
  ip_zero = c_db.prepare('SELECT COUNT(ip) from ips WHERE ip = :ip')
  ip_zero.execute('ip' => i)
  result = nil
  ip_zero = ip_zero.each { |count| result = count }
  ip_zero.close
  if result.shift.equal?(0)
    c_db.execute("INSERT INTO ips (ip, count)
		VALUES(?, ?)", [i, c])
  else
    update_success_count = c_db.prepare("UPDATE ips SET count = count +
		 :count WHERE ip = :ip")
    update_success_count.execute({ "count": c, "ip": i })
    update_success_count.close
  end
end
