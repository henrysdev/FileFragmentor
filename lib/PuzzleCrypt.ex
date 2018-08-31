defmodule PuzzleCrypt do

	# aes encrypt a given chunk with provided password
	def encrypt(fragment, password) do
		IO.puts("[Encrypting] - password=#{password}")
		# todo
		fragment
	end

	# sha256 hash (aes_key + seqID)
	def hmac(fragment, password) do
		sequence_id = elem(fragment, 1)
		IO.puts("[HMAC] - sha256(#{password} + #{sequence_id})")
		# todo
		fragment
	end

	# format and write out fragment to disk
	def write_out(fragment) do
		sequence_id = elem(fragment, 1)
		IO.puts("[Write-Out] - Fragment #{sequence_id}")
		IO.puts(elem(fragment, 0))
		# todo
	end

	# evenly distribute file bytes over fragments
	def merge_rem(remainders, last, last) do
		[Enum.join(remainders)]
	end
	def merge_rem([ head | _tail ], count, frag_count) do
		[ new_head | _new_tail ] = _tail
		[ head ] ++ merge_rem([ new_head | _new_tail ], count + 1, frag_count)
	end

	# fragment file into n parts
	def fragment(password, fpath, frag_count) do
		%{size: size} = File.stat! fpath
		# todo: throw error if frag_count > size
		chunksize = div(size, frag_count)
		File.stream!(fpath, [], chunksize)
			|> Enum.to_list
			|> merge_rem(1, frag_count)
			|> Enum.map(fn(chunk) -> encrypt(chunk, password) end)
			|> Stream.with_index
			|> Enum.map(fn(frag) -> hmac(frag, password) end)
			|> Enum.each(fn(frag) -> write_out(frag) end)
	end

	# reassemble n parts into single file
	def reassemble(password, folderpath) do
		IO.puts("reassemble")
	end

end