import arrow.core.Either
import arrow.core.left
import arrow.core.right
import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.subcommands
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.arguments.help
import com.github.ajalt.clikt.parameters.options.help
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.path
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.google.gson.ToNumberPolicy
import org.bouncycastle.crypto.digests.Blake2bDigest
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import java.util.*
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import kotlin.io.path.exists
import kotlin.io.path.name

const val DIGEST_SIZE: Int = 18

private fun computeChecksum(data: ByteArray, offset: Int, length: Int): String {
    val blake = Blake2bDigest(null, DIGEST_SIZE, null, null)
    val out = ByteArray(DIGEST_SIZE)
    val enc = Base64.getEncoder()

    blake.update(data, offset, length)
    blake.doFinal(out, 0)
    return enc.encodeToString(out)
}

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

// Only for testing
fun saveBlockmapAsOneBlock(exePath: Path, blockmapPath: Path) {
    val bytes = Files.readAllBytes(exePath)
    val size = bytes.size
    val checksum = computeChecksum(bytes, 0, size)

    Files.newOutputStream(blockmapPath).use {
        GZIPOutputStream(it).use { gzipOututStream ->
            OutputStreamWriter(gzipOututStream, StandardCharsets.UTF_8).use { writer ->
                writer.write("""{"version":"2","files":[{"name":"file","offset":0,"checksums":["$checksum"],"sizes":[$size]}]}""")
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

    for ((offsetSize, checksum) in offsetSizePairs.zip(checksumSeq)) {
        val (ofs, len) = offsetSize
        if (ofs + len >= data.size) {
            break
        }

        val d = computeChecksum(data, ofs, len)
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

fun loadPackageJson(jsonPath: Path): Map<*, *> {
    Files.newInputStream(jsonPath).buffered().use {
        InputStreamReader(it, StandardCharsets.UTF_8).use { reader ->
            val jsonContent = reader.readText()
            val gson: Gson = GsonBuilder().create()
            return gson.fromJson(jsonContent, Map::class.java)
        }
    }
}

fun currentDatetime(): String {
    val currentDateTime = LocalDateTime.now()
    val formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
    val formattedDateTime = currentDateTime.format(formatter)
    return formattedDateTime
}

fun generateYaml(exePath: Path, jsonPath: Path?) {
    val md: MessageDigest = MessageDigest.getInstance("SHA-512")
    val enc = Base64.getEncoder()

    val fileName = exePath.fileName
    val data = exePath.toFile().readBytes()
    val fileSize = data.count()

    val messageDigest = md.digest(data)
    val sha512 = enc.encodeToString(messageDigest)

    val version = jsonPath?.let { loadPackageJson(it)["version"] } ?: "FIXME"
    val datetime = currentDatetime()

    println(
        """version: $version
files:
  - url: $fileName
    sha512: $sha512
    size: $fileSize
path: $fileName
sha512: $sha512
releaseDate: '$datetime'
""".trimIndent()
    )
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

class GenYaml : CliktCommand() {
    private val path: Path by argument().path(mustExist = true).help("Path to executable")
    private val jsonPath: Path? by option("--json").path(mustExist = true).help("Path to package.json")

    override fun run() {
        generateYaml(path, jsonPath)
    }
}

class WriteBlockmap1 : CliktCommand() {
    private val exePath: Path by argument().path(mustExist = true).help("Path to executable")

    override fun run() {
        val blockmapPath = exePath.resolveSibling(exePath.name + ".blockmap")
        if (blockmapPath.exists()) {
            throw FileAlreadyExistsException(blockmapPath.toFile())
        }

        saveBlockmapAsOneBlock(exePath, blockmapPath)
    }
}

class MainCommand : CliktCommand() {
    override fun run() {}
}

fun main(args: Array<String>) {
    MainCommand().subcommands(Verify(), Compare(), GenYaml(), WriteBlockmap1()).main(args)
}
