# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"
require "set"
#require "thread_safe"
require "json"
# require "rubyforge"
# require "pr_geohash"
#
# This filter will look for a field from an event and enrich later events that
# match the same identifier with their proper name.
#
# The config looks like this:
#
#     filter {
#       geohashcid { }
#     }
#

class LogStash::Filters::GeoHashCid < LogStash::Filters::Base

  config_name "geohashcid"
  milestone 1

  public
  def initialize(config = {})
    super


  end # def initialize

  public
  def register
    # This filter needs to keep state.
    if @lcg_data.nil?
      lcg_file = ::File.join(::File.expand_path("../../../vendor/", ::File.dirname(__FILE__)), "lcg.json")
      if !File.exists?(lcg_file)
        raise "Couldn't find the lcg.json (I looked for '#{lcg_file}')"
      end
      @lcg_data = JSON.load(lcg_file)
      @average_time = 0
    end
  end # def register

  public
  def filter(event)
    return unless filter?(event)

    data = event['data']
    return if data.nil?
    cid_info = data['cid_info']
    return if cid_info.nil?
    return if cid_info['e164'].nil?
    return if not cid_info['e164_valid']
    return if cid_info['region'] != 'US'
    start = Time.now()

    cid = cid_info['e164'][2,6]
    data = @lcg_data[cid]
    return if data.nil?
    event['location_geojson'] = [data['lon'],data['lat']]
    event['location'] = {"lat" => data['lat'], "lon" => data['lon']}
    duration = Time.now() - start
    if duration > 0.01 && duration > @average_time
        logger.warn("Geohashcid: Took #{duration.round(3)} which is longer than average of #{@average_time.round(3)}", :event => event)
    end
    @average_time = (@average_time + duration) / 2
  end
end
