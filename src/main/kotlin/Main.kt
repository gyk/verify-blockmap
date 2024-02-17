import arrow.core.Either
import arrow.core.left
import arrow.core.right
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.ToNumberPolicy
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.arguments.*
import com.github.ajalt.clikt.parameters.options.*
import com.github.ajalt.clikt.parameters.types.path
import java.io.InputStreamReader
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64
import java.util.zip.GZIPInputStream
import org.bouncycastle.crypto.digests.Blake2bDigest

const val DIGEST_SIZE: Int = 18

fun loadBlockmap(blockmapPath: Path): Map<*, *> {
    Files.newInputStream(blockmapPath).buffered().use {
        GZIPInputStream(it).use { gzipInputStream ->
            InputStreamReader(gzipInputStream, StandardCharsets.UTF_8).use { reader ->
                val jsonContent = reader.readText()
                val gson: Gson = GsonBuilder()
                    .setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE)
                    .create()
                return gson.fromJson(jsonContent, Map::class.java)
            }
        }
    }
}

fun loadMetadataFromBlockmap(blockmapPath: Path): Map<*, *>? {
    val m = loadBlockmap(blockmapPath)
    if (m["version"] != "2") {
        println("WARNING: Version ${m["version"]} is not supported.")
    }
    val files = m["files"]

    if (files is List<*>) {
        if (files.size > 1) {
            println("WARNING: More than 1 file.")
        }

        return files.first() as? Map<*, *>
    }

    return null
}

fun getOffsetSizePairs(offset: Int, sizes: Sequence<Int>): Sequence<Pair<Int, Int>> {
    val offsets = sizes.scan(offset) { acc, x -> acc + x }
    return offsets.zip(sizes)
}

sealed class VerificationResult {
    data class Ok(val nBlocks: Int) : VerificationResult()
    data class Invalid(val message: String) : VerificationResult()
    data class Failed(val message: String) : VerificationResult()
}

fun verifyDataByMetadata(data: ByteArray, metadata: Map<*, *>): VerificationResult {
    val offset = metadata["offset"] as? Int ?: 0
    val checksums =
        metadata["checksums"] as? List<*> ?: return VerificationResult.Invalid("'checksums' is not a valid array")
    val sizes = metadata["sizes"] as? List<*> ?: return VerificationResult.Invalid("'sizes' is not a valid array")
    if (checksums.size != sizes.size) {
        return VerificationResult.Invalid("The lengths of 'checksums' and 'sizes' are not the same")
    }

    val offsetSizePairs = getOffsetSizePairs(offset, sizes.asSequence().map { (it as Long).toInt() })
    val checksumSeq = checksums.asSequence().map { it as String }

    val blake = Blake2bDigest(null, DIGEST_SIZE, null, null)
    val out = ByteArray(DIGEST_SIZE)
    val enc = Base64.getEncoder()

    for ((offsetSize, checksum) in offsetSizePairs.zip(checksumSeq)) {
        val (ofs, len) = offsetSize
        if (ofs + len >= data.size) {
            break
        }
        blake.reset()
        blake.update(data, ofs, len)
        blake.doFinal(out, 0)
        val d = enc.encodeToString(out)
        if (d != checksum) {
            return VerificationResult.Failed(
                String.format(
                    "The digest of block (offset = $ofs, len = $len) does NOT match checksum $checksum"
                )
            )
        }
    }
    return VerificationResult.Ok(checksums.size)
}

fun verify(exePath: Path) {
    val blockmapPath = exePath.resolveSibling("${exePath.fileName}.blockmap")
    val data = exePath.toFile().readBytes()
    val metadata = loadMetadataFromBlockmap(blockmapPath)
    if (metadata != null) {
        when (val res = verifyDataByMetadata(data, metadata)) {
            is VerificationResult.Ok ->
                println("Succeed to verify ${res.nBlocks} blocks")

            is VerificationResult.Invalid ->
                println("Invalid metadata: ${res.message}")

            is VerificationResult.Failed ->
                println("Verification failed: ${res.message}")
        }
    }
}

fun compare(oldPath: Path, newPath: Path): Either<String, Unit> {
    fun load(p: Path): Either<String, Sequence<Pair<String, Int>>> {
        val metadata =
            loadMetadataFromBlockmap(p) ?: return "Unable to load metadata".left()
        val checksums =
            metadata["checksums"] as? List<*>
                ?: return "'checksums' is not a valid array".left()
        val sizes =
            metadata["sizes"] as? List<*> ?: return "'sizes' is not a valid array".left()
        if (checksums.size != sizes.size) {
            return "The lengths of 'checksums' and 'sizes' are not the same".left()
        }

        return checksums.asSequence().map { it as String }
            .zip(sizes.asSequence().map { (it as Long).toInt() })
            .map { (checksum, size) ->
                checksum to size
            }.right()
    }

    val m = load(oldPath).fold(
        { return it.left() },
        { it.toMap() }
    )

    var skipped: Long = 0
    var total: Long = 0

    for ((checksum, size) in load(newPath).fold(
        { return it.left() },
        { it }
    )) {
        total += size
        if (m.containsKey(checksum) && m[checksum] == size) {
            skipped += size
        }
    }

    val ratio = skipped.toFloat() / total
    println("total = ${total}, skipped = ${skipped}, ratio = ${"%.2f%%".format(ratio * 100)}")
    return Unit.right()
}

class Verify : CliktCommand() {
    private val path: Path by argument().path(mustExist = true).help("Path to executable")

    override fun run() {
        verify(path)
    }
}

class Compare : CliktCommand() {
    private val oldPath: Path? by option("--old").path(mustExist = true).help("Path to old blockmap")
    private val newPath: Path? by option("--new").path(mustExist = true).help("Path to new blockmap")

    override fun run() {
        compare(oldPath!!, newPath!!)
    }
}

class MainCommand : CliktCommand() {
    override fun run() {}
}

fun main(args: Array<String>) {
    MainCommand().subcommands(Verify(), Compare()).main(args)
}
