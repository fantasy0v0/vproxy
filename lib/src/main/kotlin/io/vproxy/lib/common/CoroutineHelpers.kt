package io.vproxy.lib.common

import kotlinx.coroutines.*
import io.vproxy.base.connection.Connection
import io.vproxy.base.connection.NetEventLoop
import io.vproxy.base.connection.ServerSock
import io.vproxy.base.selector.SelectorEventLoop
import io.vproxy.base.selector.TimerEvent
import io.vproxy.base.util.LogType
import io.vproxy.base.util.Logger
import io.vproxy.base.util.callback.Callback
import io.vproxy.base.util.promise.Promise
import io.vproxy.base.util.thread.VProxyThread
import vproxy.lib.tcp.CoroutineConnection
import vproxy.lib.tcp.CoroutineServerSock
import java.time.Duration
import java.util.*
import java.util.concurrent.*
import java.util.concurrent.atomic.AtomicReference
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

private val defaultCoroutineEventLoop = _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop.open()

fun defaultCoroutineEventLoop(): _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop {
  if (defaultCoroutineEventLoop.runningThread == null) {
    defaultCoroutineEventLoop.loop { _root_ide_package_.io.vproxy.base.util.thread.VProxyThread.create(it, "default-coroutine-event-loop") }
  }
  return defaultCoroutineEventLoop
}

fun _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop.dispatcher(): CoroutineDispatcher {
  return VProxyCoroutineExecutor(this).asCoroutineDispatcher()
}

class VProxyScheduledFuture(
  loop: _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop,
  private val delayMs: Int,
  command: Runnable,
) : ScheduledFuture<Any> {
  val completion = AtomicReference<Boolean?>()
  private val event: _root_ide_package_.io.vproxy.base.selector.TimerEvent = loop.delay(delayMs) {
    if (completion.compareAndSet(null, true)) {
      command.run()
    }
  }

  override fun cancel(mayInterruptIfRunning: Boolean): Boolean {
    if (completion.compareAndSet(null, false)) {
      event.cancel()
      return true
    } else {
      return false
    }
  }

  override fun isCancelled(): Boolean {
    return completion.get() == false
  }

  override fun isDone(): Boolean {
    return completion.get() == true
  }

  override fun get(): Any? {
    return null
  }

  override fun get(timeout: Long, unit: TimeUnit): Any? {
    return null
  }

  override fun getDelay(unit: TimeUnit): Long {
    return unit.convert(Duration.ofMillis(delayMs.toLong()))
  }

  override fun compareTo(other: Delayed?): Int {
    var n = 0L
    if (other != null) {
      n = other.getDelay(TimeUnit.MILLISECONDS)
    }
    return (delayMs.toLong() - n).toInt()
  }
}

class VProxyCoroutineExecutor(
  private val loop: _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop,
) : AbstractExecutorService(), ScheduledExecutorService {
  override fun execute(command: Runnable) {
    loop.runOnLoop(command)
  }

  override fun schedule(command: Runnable, delay: Long, unit: TimeUnit): ScheduledFuture<*> {
    return VProxyScheduledFuture(loop, unit.toMillis(delay).toInt(), command)
  }

  override fun shutdown() {
    throw UnsupportedOperationException("should not be called")
  }

  override fun shutdownNow(): MutableList<Runnable> {
    throw UnsupportedOperationException("should not be called")
  }

  override fun isShutdown(): Boolean {
    throw UnsupportedOperationException("should not be called")
  }

  override fun isTerminated(): Boolean {
    throw UnsupportedOperationException("should not be called")
  }

  override fun awaitTermination(timeout: Long, unit: TimeUnit): Boolean {
    throw UnsupportedOperationException("should not be called")
  }

  override fun <V : Any?> schedule(callable: Callable<V>, delay: Long, unit: TimeUnit): ScheduledFuture<V> {
    throw UnsupportedOperationException("should not be called")
  }

  override fun scheduleAtFixedRate(
    command: Runnable,
    initialDelay: Long,
    period: Long,
    unit: TimeUnit
  ): ScheduledFuture<*> {
    throw UnsupportedOperationException("should not be called")
  }

  override fun scheduleWithFixedDelay(
    command: Runnable,
    initialDelay: Long,
    delay: Long,
    unit: TimeUnit
  ): ScheduledFuture<*> {
    throw UnsupportedOperationException("should not be called")
  }
}

suspend fun <T> _root_ide_package_.io.vproxy.base.util.promise.Promise<T>.await(): T {
  return suspendCancellableCoroutine { cont: CancellableContinuation<T> ->
    this.setHandler { res, err ->
      if (err != null) {
        cont.resumeWithException(err)
      } else {
        cont.resume(res)
      }
    }
  }
}

suspend fun <T, E : Throwable> awaitCallback(f: (_root_ide_package_.io.vproxy.base.util.callback.Callback<T, E>) -> Unit): T {
  return suspendCancellableCoroutine { cont: CancellableContinuation<T> ->
    f(object : _root_ide_package_.io.vproxy.base.util.callback.Callback<T, E>() {
      override fun onSucceeded(value: T) {
        cont.resume(value)
      }

      override fun onFailed(err: E) {
        cont.resumeWithException(err)
      }
    })
  }
}

suspend fun sleep(millis: Int) {
  return suspendCancellableCoroutine { cont: CancellableContinuation<Unit> ->
    _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop.current().delay(millis) { cont.resume(Unit) }
  }
}

class VProxyCoroutineCodeBlock {
  private val deferList = LinkedList<() -> Unit>()

  fun defer(run: () -> Unit) {
    deferList.add(run)
  }

  internal fun runDefer() {
    while (true) {
      val f = deferList.pollLast() ?: break
      try {
        f()
      } catch (e: Throwable) {
        _root_ide_package_.io.vproxy.base.util.Logger.error(_root_ide_package_.io.vproxy.base.util.LogType.IMPROPER_USE, "exception thrown in deferred function", e)
      }
    }
  }
}

@Suppress("ClassName")
object vplib {
  object coroutine {
    suspend fun <T> run(exec: suspend VProxyCoroutineCodeBlock.() -> T): T {
      val block = VProxyCoroutineCodeBlock()
      try {
        return exec(block)
      } finally {
        block.runDefer()
      }
    }

    fun with(vararg resources: AutoCloseable): VProxyCoroutineLauncher {
      val launcher = VProxyCoroutineLauncher(resources)
      val loop = _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop.current()
      if (loop == null) {
        launcher.release()
        throw IllegalStateException("currently not on any event loop: " + Thread.currentThread())
      }
      launcher.loop = loop
      return launcher
    }

    fun launch(exec: suspend VProxyCoroutineCodeBlock.() -> Unit) {
      val loop = _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop.current() ?: throw IllegalStateException("currently not on any event loop: " + Thread.currentThread())
      loop.launch(exec)
    }
  }
}

class VProxyCoroutineLauncher internal constructor(
  private val resources: Array<out AutoCloseable>,
) {
  internal var loop: _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop? = null
  private var started = false

  fun launch(exec: suspend VProxyCoroutineCodeBlock.() -> Unit) {
    if (started) {
      throw IllegalStateException("already started")
    }
    started = true

    loop!!.launch {
      defer { release() }
      exec()
    }
  }

  suspend fun <T> run(exec: suspend VProxyCoroutineCodeBlock.() -> T): T {
    if (started) {
      throw IllegalStateException("already started")
    }
    started = true

    return vplib.coroutine.run {
      defer { release() }
      exec(this)
    }
  }

  fun <T> execute(f: suspend VProxyCoroutineCodeBlock.() -> T): _root_ide_package_.io.vproxy.base.util.promise.Promise<T> {
    if (started) {
      throw IllegalStateException("already started")
    }
    started = true

    return loop!!.execute(f).then {
      release()
      _root_ide_package_.io.vproxy.base.util.promise.Promise.resolve(it)
    }
  }

  internal fun release() {
    for (res in resources) {
      try {
        res.close()
      } catch (e: Throwable) {
        _root_ide_package_.io.vproxy.base.util.Logger.error(_root_ide_package_.io.vproxy.base.util.LogType.IMPROPER_USE, "exception thrown when releasing $res", e)
      }
    }
  }
}

fun _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop.with(vararg resources: AutoCloseable): VProxyCoroutineLauncher {
  val launcher = VProxyCoroutineLauncher(resources)
  launcher.loop = this
  return launcher
}

fun _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop.launch(exec: suspend VProxyCoroutineCodeBlock.() -> Unit) {
  if (this.runningThread == null) {
    throw IllegalStateException("loop is not started")
  }
  val block = VProxyCoroutineCodeBlock()
  GlobalScope.launch(this.dispatcher(), CoroutineStart.DEFAULT) {
    try {
      exec(block)
    } catch (e: Throwable) {
      _root_ide_package_.io.vproxy.base.util.Logger.error(_root_ide_package_.io.vproxy.base.util.LogType.IMPROPER_USE, "coroutine thrown exception", e)
      throw e
    }
  }.invokeOnCompletion {
    block.runDefer()
  }
}

fun <T> _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop.execute(f: suspend VProxyCoroutineCodeBlock.() -> T): _root_ide_package_.io.vproxy.base.util.promise.Promise<T> {
  if (this.runningThread == null) {
    throw IllegalStateException("loop is not started")
  }
  val tup = _root_ide_package_.io.vproxy.base.util.promise.Promise.todo<T>()
  this.launch {
    val value: T
    try {
      value = f()
    } catch (e: Throwable) {
      tup.right.failed(e)
      return@launch
    }
    tup.right.succeeded(value)
  }
  return tup.left
}

@Suppress("FunctionName")
fun __getCurrentNetEventLoopOrFail(): _root_ide_package_.io.vproxy.base.connection.NetEventLoop {
  val loop = _root_ide_package_.io.vproxy.base.connection.NetEventLoop.current()
  if (loop == null) {
    val sLoop = _root_ide_package_.io.vproxy.base.selector.SelectorEventLoop.current()
    if (sLoop == null) {
      throw IllegalStateException("currently not on any event loop: " + Thread.currentThread())
    } else {
      throw IllegalStateException("net event loop not created yet: " + Thread.currentThread())
    }
  }
  return loop
}

fun _root_ide_package_.io.vproxy.base.connection.Connection.coroutine(): CoroutineConnection {
  val loop = __getCurrentNetEventLoopOrFail()
  return coroutine(loop)
}

fun _root_ide_package_.io.vproxy.base.connection.Connection.coroutine(loop: _root_ide_package_.io.vproxy.base.connection.NetEventLoop): CoroutineConnection {
  return CoroutineConnection(loop, this)
}

fun _root_ide_package_.io.vproxy.base.connection.ServerSock.coroutine(): CoroutineServerSock {
  val loop = _root_ide_package_.io.vproxy.base.connection.NetEventLoop.current()
    ?: throw IllegalStateException("currently not on any event loop or net event loop not created yet: " + Thread.currentThread())
  return coroutine(loop)
}

fun _root_ide_package_.io.vproxy.base.connection.ServerSock.coroutine(loop: _root_ide_package_.io.vproxy.base.connection.NetEventLoop): CoroutineServerSock {
  return CoroutineServerSock(loop, this)
}

/**
 * Indicate that the non-suspend function can be safely called inside a coroutine.
 * This suppresses the IDEA linter
 */
@Suppress("RedundantSuspendModifier")
suspend inline fun <T> unsafeIO(exec: () -> T): T {
  return exec()
}
