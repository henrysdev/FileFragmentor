defmodule Main do

	"""
	aes encrypt a given chunk with provided password
	"""
	def encrypt(fragment, password) do
		IO.puts("[Encrypting] - password=#{password}")
		# todo
		fragment
	end

	"""
	sha256 hash (aes_key + seqID)
	"""
	def hmac(fragment, password) do
		sequence_id = elem(fragment, 1)
		IO.puts("[HMAC] - sha256(#{password} + #{sequence_id})")
		# todo
		fragment
	end

	"""
	format and write out fragment to disk
	"""
	def write_out(fragment) do
		sequence_id = elem(fragment, 1)
		IO.puts("[Write-Out] - Fragment #{sequence_id}")
		#IO.puts(List.to_string(elem(fragment, 0)))
		IO.puts(elem(fragment, 0))
	end

	"""
	evenly distribute file bytes over fragments
	"""
	def compare_and_merge(h, h1, frag_count, frag_count), do: [ h <> h1, [ ] ]
	def compare_and_merge(_h, _h1, _, _), do: [ _h, _h1 ]

	def merge_remainder([ _h ], _, _), do: [ _h ]
	def merge_remainder([ k | _tail ], count, frag_count) do
		[ h, h1 | _t ] = [ k | _tail]
		[ h , _h1 ] = compare_and_merge(h, h1, count, frag_count)
		[ h ] ++ merge_remainder([ _h1 | _t ], count + 1, frag_count)
	end

	"""
	fragment file into n parts
	"""
	def fragment(password, fpath, frag_count) do
		%{size: size} = File.stat! fpath
		chunksize = div(size, frag_count)
		File.stream!(fpath, [], chunksize)
			|> Enum.to_list
			|> merge_remainder(1, frag_count)
			|> Enum.filter(& &1 != [ ])
			|> Enum.map(fn(chunk) -> encrypt(chunk, password) end)
			|> Stream.with_index
			|> Enum.map(fn(frag) -> hmac(frag, password) end)
			|> Enum.each(fn(frag) -> write_out(frag) end)
	end

	"""
	reassemble n parts into single file
	"""
	def reassemble(password, folderpath) do
		IO.puts("reassemble")
	end

end
