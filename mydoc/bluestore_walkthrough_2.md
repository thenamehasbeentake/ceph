class BlueStore : public ObjectStore,
		  public md_config_obs_t {

  // config observer
  const char** get_tracked_conf_keys() const override;
  void handle_conf_change(const ConfigProxy& conf,
			  const std::set<std::string> &changed) override;

配置观察者， 配置发生变化，startup会有帮助。

配置设置_set_csum 和 _set_compression

初始到内存数据结构。




_set_compression 比如
获取一个compressor的handle
  auto m = Compressor::get_comp_mode_type(cct->_conf->bluestore_compression_mode);


配置
comp_min_blob_size





  struct TransContext;

  描述上下文，记录组合成一个事务的写操作。 写到disk， 


cash/cache collections?? 
 struct BufferSpace;
 

 AioContext aio??



 
  /// cached buffer
  struct Buffer {
cache object data 将会存储到disk上的


    enum {
      STATE_EMPTY,     ///< empty buffer -- used for cache history
      STATE_CLEAN,     ///< clean data that is up to date
      STATE_WRITING,   ///< data that is being written (io not yet complete)
    };
    三种状态

不会变成dirty状态就永远不会被写入
每次做写操作，我一直会立刻把他放在disk的队列中

不同于page cache


有一个flag， 
    enum {
      FLAG_NOCACHE = 1,  ///< trim when done WRITING (do not become CLEAN)
      // NOTE: fix operator<< when you define a second flag
    };
判断buffer是否需要写到盘上，因为有时候我们执行一个想要cache写操作的模式，在他们在内存中完成之后，直到他们因为LRU失败。

其他情况下我们不希望cache write.除非客户端刻意为之，这种情况我们仍然要在内存中保持住它，有一个读操作，或者需要pipeline第二个写操作但是一旦它实际提交了那么我们设置这个flag？？？？






状态链表，确认所有正在写的buffers。在帮助，获取数据结尾，可能重新分配缓存链表，

    boost::intrusive::list_member_hook<> state_item;









下一个级别的缓存，单个对象，一系列文件偏移的映射，或者对象的偏移到buffer，内核中属于地址空间，
  /// map logical extent range (object) onto buffers
  struct BufferSpace {
    enum {
      BYPASS_CLEAN_CACHE = 0x1,  // bypass clean cache
    };




map， offset to buffer

    mempool::bluestore_cache_meta::map<uint32_t, std::unique_ptr<Buffer>>
      buffer_map;



这些操作有一点小技巧，包含BufferSpace的cache，



    void write(BufferCacheShard* cache, uint64_t seq, uint32_t offset, ceph::buffer::list& bl,
	       unsigned flags) {
      std::lock_guard l(cache->lock);
      // 特殊的offset buffer
      Buffer *b = new Buffer(this, Buffer::STATE_WRITING, seq, offset, bl,
			     flags);
      b->cache_private = _discard(cache, offset, bl.length());
      _add_buffer(cache, b, (flags & Buffer::FLAG_NOCACHE) ? 0 : 1, nullptr);
      cache->_trim();




实际写到盘上之后调用。
    void _finish_write(BufferCacheShard* cache, uint64_t seq);
去掉writing状态，

did_read做类似的事情，在我们执行一个read 。把数据丢到buffer cache， flag将被合适的设置，











  /// in-memory shared blob state (incl cached buffers)
  struct SharedBlob {


