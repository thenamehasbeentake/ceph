实现ObjectStore接口，最小阻碍objectstore合法的设计


objectstore 有两种读操作，同步阻塞读，stat  , getattr,   read a little lock
write ， 所有的操作都是在事务下完成, 捕获collection下的ops，自动请求、自动提交

## class BlueStore : public ObjectStore,

bluestore直接写到裸设备，在rocksdb上保存metadata，rocksdb需要读写文件，所以共享bluestore存储的块设备。需要rocksdb共享同样的块设备


## KeyValueDB

KeyValueDB是ceph数据库的抽象，无论是rocksdb，memdb...

在keyvaluedb里面由rocksdb的抽象调用，wrap包装了POSIX调用，file open \read\write。。。

是在目录里面backend的接口


## class BlueRocksEnv : public rocksdb::EnvWrapper



BlueRocksEnv这个接口里面，需要实现的都是一些简单的操作，没有rename。目录结构只有一层深度，写一个相当简单的文件系统是非常容易的，用来满足rocksdb的需求




这个文件系统被称之为bluefs


## class BlueFS;

class BlueRocksEnv : public rocksdb::EnvWrapper {


bluefs单独的class, 实现简单的文件系统，

blue layer ???  实现rocksdb接口， 光头接口？   直接把任何调用，传递给bluefs，
写了很多，但是主要思想是有文件存在，比如简单的目录，1或者2的深度，
可以
~~~
  int open_for_write(
    std::string_view dir,
    std::string_view file,
    FileWriter **h,
    bool overwrite);

  int open_for_read(
    std::string_view dir,
    std::string_view file,
    FileReader **h,
    bool random = false);
~~~

可以得到FileWriter， FileReader



FileWriter也非常简单，可以

    void append(const char *buf, size_t len) {

可以flush (没了)，  filewriter上累计的所有脏数据
    uint64_t get_effective_write_pos() {




    
bluefs implement的方式,有一些数量的块设备，允许写入


##  std::vector<BlockDevice*> bdev;                  ///< block devices we can use

裸设备的内部抽象，

BlockDevice是低级别的抽象，wrap包装了一个bock 设备，抽象类，一系列不同...

提供一些基本操作， 假定block对齐的read， 

  virtual int read(
    uint64_t off,
    uint64_t len,
    ceph::buffer::list *pbl,


非block对齐的read_random， 读buffer而不是bufferlist
  virtual int read_random(
    uint64_t off,
    uint64_t len,
    char *buf,
    bool buffered) = 0;


  virtual int write(
    uint64_t off,
    ceph::buffer::list& bl,
    bool buffered,
    int write_hint = WRITE_LIFE_NOT_SET) = 0;
阻塞的read \ write







aid_read, aio_write 非阻塞的， IOContext。aio的描述符，异步，flush保证每一个write 在flush之前完成，然后hardware保证实际上提交到disk，

  virtual int aio_read(
    uint64_t off,
    uint64_t len,
    ceph::buffer::list *pbl,
    IOContext *ioc) = 0;
  virtual int aio_write(
    uint64_t off,
    ceph::buffer::list& bl,
    IOContext *ioc,
    bool buffered,
    int write_hint = WRITE_LIFE_NOT_SET) = 0;



discard应对完成一半，
  virtual int discard(uint64_t offset, uint64_t len) { return 0; }
  virtual int queue_discard(interval_set<uint64_t> &to_release) { return -1; }
  virtual void discard_drain() { return; }




## struct IOContext {

IOContext描述一系列正在执行的io，内部有一些锁用来debug，

running_aios一直循环写，加速
pending_aios , 当有一个submit call , 才会说ok， 去做所有的io， 传递到kernel，kernel取做所有的io，
有一系列的方法 知道他们是都做完了。 

  std::list<aio_t> pending_aios;    ///< not yet submitted
  std::list<aio_t> running_aios;    ///< submitting or submitted


aio_wait将会阻塞，直到结束。
或者是一种回调函数，结束了告诉你，
  void release_running_aios();
  void aio_wait();
  uint64_t get_num_ios() const;




通过调用aio_write积累pending_aios，调用aio_write只会把它加入IOContext, 并且最终提交它 submit，然后就结束了






这里让我们看看bluestore的write。。。

太复杂了，先do_read

int BlueStore::_do_read(
  Collection *c,
  OnodeRef o,
  uint64_t offset,
  size_t length,
  bufferlist& bl,
  uint32_t op_flags,
  uint64_t retry_count)
{

figure out 所有的buffer， 然后

最终会调用aio_submit

 int64_t num_ios = blobs2read.size();
  if (ioc.has_pending_aios()) {
    num_ios = ioc.get_num_ios();
    bdev->aio_submit(&ioc);
    dout(20) << __func__ << " waiting for aio" << dendl;
    ioc.aio_wait();
    r = ioc.get_return_value();

然后这个地方就是提交到kernel的地方，通过block device接口。

aio_wait会阻塞，一旦提交到kernel，会有很好的读，因为我们读一个文件的多段，并行提交，等待结束。收集返回值，继续做其他工作。

这就是读怎么做的





## BlockDevice
有两种，一种kernel， wrap linux kernel libaio。可以direct read/write  , 可以O_direct  , 传递page cache, 所有的page对齐 ，    将会是一个序列

写入到一个简单的块设备，代码非常令人兴奋， 

最让人激动的代码是，打开设备， 确保正确的块大小。




void KernelDevice::_aio_thread()
{
  dout(10) << __func__ << " start" << dendl;
  int inject_crash_count = 0;

  监听所有的aio结束


系统调用，get_next_completed， 获取下一个结束的aio， 
内存中的buffer， 所有的完成都在里面， 只是pooling to拿到这个， 一旦拿到结束的aio， 

    int r = io_queue->get_next_completed(cct->_conf->bdev_aio_poll_ms,
           aio, max);
    if (r < 0) {




priv到IOContext， 这个IOContext结束了， 
 if (r > 0) {
      dout(30) << __func__ << " got " << r << " completed aios" << dendl;
      for (int i = 0; i < r; ++i) {
  IOContext *ioc = static_cast<IOContext*>(aio[i]->priv);
  _aio_log_finish(ioc, aio[i]->offset, aio[i]->length);
  if (aio[i]->queue_item.is_linked()) {
    std::lock_guard l(debug_queue_lock);
    debug_aio_unlink(*aio[i]);




然后就知道有error，加到日志里面

      
  long r = aio[i]->get_return_value();
        if (r < 0) {
          derr << __func__ << " got r=" << r << " (" << cpp_strerror(r) << ")"
         << dendl;
          if (ioc->allow_eio && is_expected_ioerr(r)) {
            derr << __func__ << " translating the error to EIO for upper layer"
     << dendl;
            ioc->set_return_value(-EIO);
          } else {
      if (is_expected_ioerr(r)) {
        note_io_error_event(






最后aio->priv,赋值到回调函数中，到bluestore的代码里面去，结束

  // call aio_wake we cannot touch ioc or aio[] as the caller
  // may free it.
  if (ioc->priv) {
    if (--ioc->num_running == 0) {
      aio_callback(aio_callback_priv, ioc->priv);
    }
  } else {
          ioc->try_aio_wake();
  }


如果没有这个priv, 那么假定有人调用blocking 和 waiting for finish , 就像是read操作

刚才show的一样，直到wake up


对于写操作，每次都会callback。



13：49





我们使用rocksdb 存所有的metadata， 所以bluefs在这些块设备之上， 
大部分blue store，写object data，由单个大的block设备， 


bluefs 更智能，相对于剩下的blue store。可以使用多个设备，这里使用vector的原因
 /*
   * There are up to 3 block devices:
   *
   *  BDEV_DB   db/      - the primary db device
   *  BDEV_WAL  db.wal/  - a small, fast device, specifically for the WAL
   *  BDEV_SLOW db.slow/ - a big, slow device, to spill over to as BDEV_DB fills
   */
  std::vector<BlockDevice*> bdev;                  ///< block devices we can use



BDEV_WAL rocksdb wal file， like a journal

BDEV_DB 


只使用部分device， 整个块设备的一些entents 交给bluefs管理 空闲空间，


简单的磁盘结构的，作为元数据journal，  append journal， 变得很大， 将会以紧凑的方式覆盖写journal。

所有修改和删除的文件，压缩出去。重写一个新journal， 如果从空文件开始。

bluefs 元数据一直在内存中， 
  // cache
  mempool::bluefs::map<std::string, DirRef, std::less<>> dir_map;          ///< dirname -> Dir
  mempool::bluefs::unordered_map<uint64_t, FileRef> file_map; ///< ino -> File

这么简单因为 不需要分配table到disk上，我们将会加载所有文件到内存，查找所有文件的分配，在内存中直到free list

使得实现非常简单，



rocksdb的文件，总是非常大，10TB的文件 -> 16/64 MB 文件，不用担心paging。



检查文件磁盘，各种打开

int BlueStore::mkfs()
{
  dout(1) << __func__ << " path " << path << dendl;
  int r;
  uuid_d old_fsid;




读bluefs目录
int BlueStore::_is_bluefs(bool create, bool* ret)
{
  if (create) {
    *ret = cct->_conf->bluestore_bluefs;
  } else {
    string s;
    int r = read_meta("bluefs", &s);
    if (r < 0) {





      // debug
      // _prepare_db_environment
    if (cct->_conf->bluestore_bluefs_env_mirror) {
      rocksdb::Env* a = new BlueRocksEnv(bluefs);
      rocksdb::Env* b = rocksdb::Env::Default();
      if (create) {
        string cmd = "rm -rf " + path + "/db " +
          path + "/db.slow " +
          path + "/db.wal";
        int r = system(cmd.c_str());
        (void)r;
      }
      env = new rocksdb::EnvMirror(b, a, false, true);
    } else {
      env = new BlueRocksEnv(bluefs);





bluestore的allocator和FreelistManager

private:
  BlueFS *bluefs = nullptr;
  bluefs_layout_t bluefs_layout;
  utime_t next_dump_on_bluefs_alloc_failure;

  KeyValueDB *db = nullptr;
  BlockDevice *bdev = nullptr;
  std::string freelist_type;
  FreelistManager *fm = nullptr;

  bluefs_shared_alloc_context_t shared_alloc;


allocator内存中数据结构，决定使用哪部分disk， 
FreelistManager部分manager，怎么实际存储在disk上。非常简单，allocate , release 

第一次mount bluestore， enumerate_reset ,  


bitmap allocator, 将disk 优雅的map，选择的key和kb数据苦，
更新freelist, 实际做一个XOR操作， 在kv中做一个merge操作， 多线程下发生变化allocate和dealocate 相互独立， 

不想要一些中心的锁， 以两个不同的线程分配空间， 如write， 不需要合作当更新key，提交事务， 以序列提交。不会打乱顺序，

两个人同时以两个线程allocator, 然后再以xor的方式merge，  LSM数据库， 






allocator
返回PExtentVector， 参数想要的大小want_size  和 chunks 大小 block_size
  virtual int64_t allocate(uint64_t want_size, uint64_t block_size,
         uint64_t max_alloc_size, int64_t hint,
         PExtentVector *extents) = 0;

  int64_t allocate(uint64_t want_size, uint64_t block_size,
       int64_t hint, PExtentVector *extents) {
    return allocate(want_size, block_size, want_size, hint, extents);
  }




stupid alloctor -> btree。 
每TB 30M内存







/// label for block device
struct bluestore_bdev_label_t {
  uuid_d osd_uuid;     ///< osd uuid
  uint64_t size = 0;   ///< device size
  utime_t btime;       ///< birth time
  std::string description;  ///< device description



open XX判断是什么type

osd_uuid 判断那个设备绑定ceph

cnode绑定collection， 每一个PG有一个collection，  hash
/// collection metadata
struct bluestore_cnode_t {
  uint32_t bits;   ///< how many bits of coll pgid are significant



offset + length
/// pextent: physical extent
struct bluestore_pextent_t : public bluestore_interval_t<uint64_t, uint32_t> 
{
  bluestore_pextent_t() {}
  bluestore_pextent_t(uint64_t o, uint64_t l) : bluestore_interval_t(o, l) {}
  bluestore_pextent_t(const bluestore_interval_t &ext) :
    bluestore_interval_t(ext.offset, ext.length) {}



 
/// extent_map: a std::map of reference counted extents
struct bluestore_extent_ref_map_t {
  struct record_t {
    uint32_t length;

多克隆下的引用计数， 




blob,  低级别代表disk上的某些region， 

/// blob: a piece of data on disk
struct bluestore_blob_t {
private:
  PExtentVector extents;              ///< raw data position on device
  uint32_t logical_length = 0;        ///< original length of data stored in the blob
  uint32_t compressed_length = 0;     ///< compressed length if any

public:






/// onode: per-object metadata
struct bluestore_onode_t {
  uint64_t nid = 0;                    ///< numeric id (locally unique)
  uint64_t size = 0;                   ///< object size
  // mempool to be assigned to buffer::ptr manually
  std::map<mempool::bluestore_cache_meta::string, ceph::buffer::ptr> attrs;


  std::vector<shard_info> extent_map_shards; ///< extent std::map shards (if any)
onode对应很多blob， shard它， 从哪儿开始到哪儿结束大小是多少，逻辑大小， 





39：33

  


bluestore 做写操作，决定写的空间， 做对象写操作，决定数据怎么从allocato一些数据，写数据到disk，做flush操作， 确保数据持久话，然后提交事务到rocksdb

有时会发生覆盖写到一个已经存在的blob，需要做read-modify-write操作，或者不想做一个小IO flush，效率低， 所有做一个defferred op/ write 










40:54 read path




int BlueStore::getattr(
  CollectionHandle &c_,
  const ghobject_t& oid,






  需要CollectionHandle， 调用open_collection拿到这个handle
  // ---------------
// read operations

ObjectStore::CollectionHandle BlueStore::open_collection(const coll_t& cid)
{
  return _get_collection(cid);
}



open_collection调用_get_collection。
获取 std::shared_lock l(coll_lock)， 在collection map上锁coll_map， 


// ---------------
// cache

BlueStore::CollectionRef BlueStore::_get_collection(const coll_t& cid)
{
  std::shared_lock l(coll_lock);
  ceph::unordered_map<coll_t,CollectionRef>::iterator cp = coll_map.find(cid);
  if (cp == coll_map.end())
    return CollectionRef();
  return cp->second;
}





collection需要引用会osd， 无论如何直接到结构体？？ 
有任何新的loopup，对于每个collection，记录到OnodeSpace onode_map;
OnodeSpace  是hash 表，通过表格的name查找

  struct Collection : public CollectionImpl {
    BlueStore *store;
    OpSequencerRef osr;
    BufferCacheShard *cache;       ///< our cache shard
    bluestore_cnode_t cnode;
    ceph::shared_mutex lock =
      ceph::make_shared_mutex("BlueStore::Collection::lock", true, false);

    bool exists;





所有当我们getattr时，其他人已经拿到了collection的handle了， 他们把handle作为参数传递进来，我们提交一个读写锁

get_onode 查找它，如果没找到标记为不存在。
如果找到了，但是没数据，那就是标记为没数据。


、、、
int BlueStore::getattr(
  CollectionHandle &c_,
  const ghobject_t& oid,
  const char *name,
  bufferptr& value)
{
  Collection *c = static_cast<Collection *>(c_.get());
  dout(15) << __func__ << " " << c->cid << " " << oid << " " << name << dendl;
  if (!c->exists)
    return -ENOENT;

  int r;
  {
    std::shared_lock l(c->lock);



get_onode, 确保collecion与pg匹配， omap中找到了就返回，
从disk上rocksdb获取到，需要一些io， 所有的cache存在mempool里面，


BlueStore::OnodeRef BlueStore::Collection::get_onode(
  const ghobject_t& oid,
  bool create,
  bool is_createop)



然后我们做store->db->get， 啥都没拿到说明不在里面。
这个时候根据情况可以create它，如果是一个新的object
onode_map中加入它, （初始化extent_map 没了）


    // new object, new onode
    on = new Onode(this, oid, key);
  } else {
    // loaded
    ceph_assert(r >= 0);
    on = Onode::decode(this, oid, key, v);
  }
  o.reset(on);
  return onode_map.add(oid, o);



























  read, 传入参数CollectionHandle， get_onode， 


  int BlueStore::read(
  CollectionHandle &c_,
  const ghobject_t& oid,
  uint64_t offset,
  size_t length,
  bufferlist& bl,
  uint32_t op_flags)
{
  auto start = mono_clock::now();
  Collection *c = static_cast<Collection *>(c_.get());
  const coll_t &cid = c->get_cid();
  dout(15) << __func__ << " " << cid << " " << oid
       << " 0x" << std::hex << offset << "~" << length << std::dec
       << dendl;


然后我们到_do_read




判断是否要cache
 if (op_flags & CEPH_OSD_OP_FLAG_FADVISE_WILLNEED) {
    dout(20) << __func__ << " will do buffered read" << dendl;
    buffered = true;


当它做完fault_range 在extent_map上，确保allocation的元数据 部分object 加载到cache中，
  o->extent_map.fault_range(db, offset, length);


extent_map是map offset到blob的结构体，
extent和extentmap 介绍之后，
这里查找start所在 对于一个特殊的offset所在哪一片shard

  auto start = seek_shard(offset);
  auto last = seek_shard(offset + length);




如果没有load进来，我们得自己load， p->loaded，
  while (start <= last) {
    ceph_assert((size_t)start < shards.size());
    auto p = &shards[start];
    if (!p->loaded) {
      dout(30) << __func__ << " opening shard 0x" << std::hex
           << p->shard_info->offset << std::dec << dendl;
      bufferlist v;
      generate_extent_shard_key_and_apply(


!p->loaded) {

generate_extent_shard_key_and_apply

db->get(

     p->extents = decode_some(v);
      p->loaded = true;





fault_range结束之后，我们获得对象这部分 所有的元数据  
  // build blob-wise list to of stuff read (that isn ‘’t cached)
  ready_regions_t ready_regions;
  blobs2read_t blobs2read;
  _read_cache(o, offset, length, read_cache_policy, ready_regions, blobs2read);


构建所有blob的map
_read_cache中， seek_lextent， 找到extent mp 下哪些blob下的 那些数据需要读， 


我们先从buffer cache中查找，
    ready_regions_t cache_res;
    interval_set<uint32_t> cache_interval;
    bptr->shared_blob->bc.read(






没找到
 // merge regions
        {
          uint64_t r_off = b_off;
          uint64_t r_len = l;
          uint64_t front = r_off % chunk_size;
          if (front) {
            r_off -= front;
            r_len += front;
          }
          unsigned tail = r_len % chunk_size;
          if (tail) {
            r_len += chunk_size - tail;
          }
          bool merged = false;
          regions2read_t& r2r = blobs2read[bptr];
          if (r2r.size()) {
            read_req_t& pre = r2r.back();
            if (r_off <= (pre.r_off + pre.r_len)) {
              front += (r_off - pre.r_off);
              pre.r_len += (r_off + r_len - pre.r_off - pre.r_len);
              pre.regs.emplace_back(region_t(pos, b_off, l, front));
              merged = true;
            }
          }
          if (!merged) {
            read_req_t req(r_off, r_len);
            req.regs.emplace_back(region_t(pos, b_off, l, front));
            r2r.emplace_back(std::move(req));
          }
        }

54：21

_prepare_read_ioc
IOContext 有可能是aio， 异步io，我们将遍历blob， 
如果是经过压缩的，而我们只读其中一小部分，也要解压整个



compressed_blob_bls->push_back(bufferlist());
      bufferlist& bl = compressed_blob_bls->back();
      auto r = bptr->get_blob().map(
        0, bptr->get_blob().get_ondisk_length(),
        [&](uint64_t offset, uint64_t length) {
          int r = bdev->aio_read(offset, length, &bl, ioc);
          if (r < 0)

某种情况我们会使用aio去读，
如果面对多个blob读的情况，我们有aio线程处理aio完成，所以这边可以把同步io变成异步io。
(现在全都变成aio了...)



如果没有压缩，只需要读一部分。
 // read the pieces
      for (auto& req : r2r) {
        dout(20) << __func__ << "    region 0x" << std::hex
                 << req.regs.front().logical_offset
                 << ": 0x" << req.regs.front().blob_xoffset
                 << " reading 0x" << req.r_off
                 << "~" << req.r_len << std::dec
                 << dendl;

        // read it
        auto r = bptr->get_blob().map(
          req.r_off, req.r_len,
          [&](uint64_t offset, uint64_t length) {
            int r = bdev->aio_read(offset, length, &req.bl, ioc);
            if (r < 0)
              return r;



如果有pending的aio，submit然后 aio_wait等待做完。

  if (ioc.has_pending_aios()) {
    num_ios = ioc.get_num_ios();
    bdev->aio_submit(&ioc);
    dout(20) << __func__ << " waiting for aio" << dendl;
    ioc.aio_wait();




_generate_read_result_bl:

累加解压后的blobs，   对于压缩的的blob， 计算它的checksum， _verify_csum
buffered 如果是带缓存的读，把它读到缓存中bc.did_read

  bool csum_error = false;
  r = _generate_read_result_bl(o, offset, length, ready_regions,
                              compressed_blob_bls, blobs2read,
                              buffered, &csum_error, bl);
  if (csum_error) {



对于非压缩的blob，只验证它的checksum


最后append到一起， 如果有空洞，就填充0，
  // generate a resulting buffer
  auto pr = ready_regions.begin();
  auto pr_end = ready_regions.end();
  uint64_t pos = 0;
  while (pos < length) {
    if (pr != pr_end && pr->first == pos + offset) {
      dout(30) << __func__ << " assemble 0x" << std::hex << pos
               << ": data from 0x" << pr->first << "~" << pr->second.length()
               << std::dec << dendl;
      pos += pr->second.length();
      bl.claim_append(pr->second);
      ++pr;
    } else {
      uint64_t l = length - pos;
      if (pr != pr_end) {
        ceph_assert(pr->first > pos + offset);
        l = pr->first - (pos + offset);
      }
      dout(30) << __func__ << " assemble 0x" << std::hex << pos
               << ": zeros for 0x" << (pos + offset) << "~" << l
               << std::dec << dendl;
      bl.append_zero(l);
      pos += l;
    }

对于compression， 有个bluestore_compression_header_t结构体











59：10